// Licensed under the Apache-2.0 license

//! Tests for detecting a key mismatch between the authorization manifest and
//! the Caliptra firmware image.
//!
//! The runtime `SET_AUTH_MANIFEST` handler verifies the vendor/owner public
//! keys carried in the auth manifest against the vendor/owner keys anchored in
//! the Caliptra firmware image (`persistent_data.manifest1.preamble`). If the
//! keys that signed the manifest's public keys do not correspond to the keys in
//! the firmware image, verification fails with a signature-invalid error. This
//! is the "key mismatch across auth manifest and Caliptra fw image" case.
//!
//! These tests load an already-signed Caliptra firmware image bundle and an
//! authorization manifest *from disk*, boot the existing emulator HW model with
//! the firmware image, and send the manifest via `SET_AUTH_MANIFEST`.
//!
//! To inject your own binaries, use `test_auth_manifest_from_disk` (see the env
//! vars documented on that test). The remaining tests generate binaries with
//! known matching / mismatching keys, write them to disk, and load them back,
//! serving both as regression tests and as templates for the disk-load flow.

use crate::common::assert_error;
use crate::test_set_auth_manifest::{
    auth_manifest_key_config, create_auth_manifest, create_auth_manifest_with_key_configs,
    create_auth_manifest_wrong_key,
};
use caliptra_api::SocManager;
use caliptra_auth_man_types::{
    AuthManifestFlags, AuthorizationManifest, ImageMetadataFlags, AUTH_MANIFEST_MARKER,
};
use caliptra_builder::{
    firmware::{APP_WITH_UART, FMC_WITH_UART},
    ImageOptions,
};
use caliptra_common::mailbox_api::{
    AuthorizeAndStashReq, AuthorizeAndStashResp, CommandId, ImageHashSource, MailboxReq,
    MailboxReqHeader, SetAuthManifestReq,
};
use caliptra_error::CaliptraError;
use caliptra_hw_model::{BootParams, DefaultHwModel, Fuses, HwModel, InitParams, ModelError};
use caliptra_image_fake_keys::*;
use caliptra_image_types::{ImageEccPubKey, ImageEccSignature, ImageManifest, MANIFEST_MARKER};
use caliptra_runtime::{
    RtBootStatus, IMAGE_AUTHORIZED, IMAGE_HASH_MISMATCH, IMAGE_NOT_AUTHORIZED, PL0_PAUSER_FLAG,
};
use openssl::bn::BigNum;
use openssl::ec::{EcGroup, EcKey};
use openssl::ecdsa::EcdsaSig;
use openssl::nid::Nid;
use openssl::sha::sha384;
use std::fs;
use std::path::Path;
use zerocopy::{FromBytes, IntoBytes};

fn swap_word_bytes_inplace(words: &mut [u32]) {
    for word in words.iter_mut() {
        *word = word.swap_bytes()
    }
}

fn bytes_to_be_words_48(buf: &[u8; 48]) -> [u32; 12] {
    let mut result: [u32; 12] = zerocopy::transmute!(*buf);
    swap_word_bytes_inplace(&mut result);
    result
}

/// Boot the emulator HW model with the given (already-signed) Caliptra firmware
/// image bytes, then send the given authorization-manifest bytes via
/// `SET_AUTH_MANIFEST` and assert on the outcome.
///
/// The vendor/owner public-key hashes are derived from the firmware image and
/// written to fuses so the image boots regardless of security state; the
/// auth-manifest key check being exercised happens later, in the runtime.
///
/// * `expected_err == None` -> the command must succeed (keys match).
/// * `expected_err == Some(e)` -> the command must fail with error `e`.
pub fn boot_and_set_auth_manifest(
    fw_image: &[u8],
    auth_manifest: &[u8],
    lms_verify: bool,
    expected_err: Option<CaliptraError>,
) {
    let mut model = boot_model_with_fw_image(fw_image, lms_verify);
    let result = send_set_auth_manifest(&mut model, auth_manifest);
    match expected_err {
        Some(err) => assert_error(&mut model, err, result.unwrap_err()),
        None => {
            result
                .unwrap()
                .expect("SET_AUTH_MANIFEST should have returned a response");
        }
    }
}

/// Like [`boot_and_set_auth_manifest`] but expects `SET_AUTH_MANIFEST` to
/// succeed and returns the still-running model so the caller can issue further
/// mailbox commands (e.g. `AUTHORIZE_AND_STASH`).
pub fn boot_and_set_auth_manifest_ok(
    fw_image: &[u8],
    auth_manifest: &[u8],
    lms_verify: bool,
) -> DefaultHwModel {
    let mut model = boot_model_with_fw_image(fw_image, lms_verify);
    send_set_auth_manifest(&mut model, auth_manifest)
        .unwrap()
        .expect("SET_AUTH_MANIFEST should have returned a response");
    model
}

/// Strip the 16-byte legacy header if present and return the `CMAN`-aligned
/// slice, asserting a valid Caliptra image-manifest marker.
fn normalize_fw_image(fw_image: &[u8]) -> &[u8] {
    // Some tooling prepends a fixed-size legacy header ahead of the raw Caliptra
    // image bundle. If the `CMAN` marker is not at the start, strip that header
    // and retry once. Otherwise a wrapped fw image surfaces only as an opaque
    // "ROM Fatal Error: 0x000B0001" (manifest marker mismatch).
    const LEGACY_HEADER_LEN: usize = 16;
    let starts_with_marker =
        |bytes: &[u8]| ImageManifest::read_from_prefix(bytes).is_ok_and(|(m, _)| m.marker == MANIFEST_MARKER);
    if starts_with_marker(fw_image) {
        fw_image
    } else {
        let stripped = fw_image.get(LEGACY_HEADER_LEN..).unwrap_or(&[]);
        assert!(
            starts_with_marker(stripped),
            "fw image does not start with a valid Caliptra image-manifest marker \
             (expected {MANIFEST_MARKER:#010x}), and stripping a {LEGACY_HEADER_LEN}-byte \
             legacy header did not reveal one either. Ensure the file is a raw Caliptra fw \
             image bundle (as produced by ImageBundle::to_bytes / the image-gen app) and not \
             the auth manifest or another format.",
        );
        stripped
    }
}

/// The image's PL0 PAUSER, if its header opts into PL0 gating (`flags` bit 0 =
/// `PL0_PAUSER_FLAG`). Commands restricted to PL0 (e.g. `AUTHORIZE_AND_STASH`)
/// must be issued with this PAUSER; otherwise they fail with
/// `RUNTIME_INCORRECT_PAUSER_PRIVILEGE_LEVEL`.
pub fn fw_image_pl0_pauser(fw_image: &[u8]) -> Option<u32> {
    let fw_image = normalize_fw_image(fw_image);
    let (manifest, _) = ImageManifest::read_from_prefix(fw_image).ok()?;
    (manifest.header.flags & PL0_PAUSER_FLAG != 0).then_some(manifest.header.pl0_pauser)
}

/// Boot the emulator HW model with the given (already-signed) Caliptra firmware
/// image, deriving the vendor/owner PK-hash fuses from the image so ROM accepts
/// it regardless of security state. Steps to `RtReadyForCommands` and returns
/// the model.
fn boot_model_with_fw_image(fw_image: &[u8], lms_verify: bool) -> DefaultHwModel {
    let fw_image = normalize_fw_image(fw_image);

    // Parse the firmware image manifest to recover the vendor/owner public keys
    // and program their hashes into the fuses, so the image is accepted by ROM.
    let (manifest, _) = ImageManifest::read_from_prefix(fw_image)
        .expect("firmware image is too small to contain an ImageManifest");
    let vendor_pk_hash =
        bytes_to_be_words_48(&sha384(manifest.preamble.vendor_pub_keys.as_bytes()));
    let owner_pk_hash = bytes_to_be_words_48(&sha384(manifest.preamble.owner_pub_keys.as_bytes()));

    // If the image designates a PL0 PAUSER outside the hw-model's default set
    // ([0,1,2,3,4]), register it as a valid mailbox PAUSER so PL0-restricted
    // commands can be issued with it (keeping the default 0x1 so boot / FW_LOAD /
    // SET_AUTH_MANIFEST still work at the default APB PAUSER). NUM_PAUSERS == 5.
    let pl0_pauser = fw_image_pl0_pauser(fw_image);
    let valid_pauser: Vec<u32> = match pl0_pauser {
        Some(p) if !(0..=4).contains(&p) => vec![p, 0, 1, 2, 3],
        _ => vec![0, 1, 2, 3, 4],
    };

    let rom = caliptra_builder::rom_for_fw_integration_tests().unwrap();
    let mut model = caliptra_hw_model::new(
        InitParams {
            rom: &rom,
            ..Default::default()
        },
        BootParams {
            fuses: Fuses {
                key_manifest_pk_hash: vendor_pk_hash,
                owner_pk_hash,
                lms_verify,
                ..Default::default()
            },
            fw_image: Some(fw_image),
            valid_pauser,
            ..Default::default()
        },
    )
    .unwrap_or_else(|e| {
        panic!(
            "the Caliptra fw image failed ROM verification during boot ({e}).\n\
             ROM must accept the fw image before the runtime auth-manifest key check can run \
             (its keys are loaded into `manifest1` on a successful boot). A ROM `Fatal Error` \
             maps to a CaliptraError, e.g. 0x000B000C = IMAGE_VERIFIER_ERR_VENDOR_ECC_SIGNATURE_INVALID \
             means the image's own vendor ECC signature did not verify.\n\
             This usually means the image was signed with a different Caliptra image-format / ROM \
             version than this checkout. Try matching the ROM via CPTRA_CI_ROM_VERSION=1.0 or 1.1, \
             or rebuild/re-sign the image with this repo's image tooling."
        )
    });

    model.step_until(|m| {
        m.soc_ifc().cptra_boot_status().read() == u32::from(RtBootStatus::RtReadyForCommands)
    });
    model
}

/// Send `SET_AUTH_MANIFEST` with the given manifest bytes (asserting a valid
/// marker) and return the raw mailbox result.
fn send_set_auth_manifest(
    model: &mut DefaultHwModel,
    auth_manifest: &[u8],
) -> Result<Option<Vec<u8>>, ModelError> {
    assert!(
        auth_manifest.len() <= SetAuthManifestReq::MAX_MAN_SIZE,
        "auth manifest ({} bytes) exceeds SET_AUTH_MANIFEST max ({} bytes)",
        auth_manifest.len(),
        SetAuthManifestReq::MAX_MAN_SIZE
    );
    let auth_manifest_marker = auth_manifest
        .get(..4)
        .map(|b| u32::from_le_bytes(b.try_into().unwrap()))
        .unwrap_or(0);
    assert_eq!(
        auth_manifest_marker, AUTH_MANIFEST_MARKER,
        "auth manifest does not start with a valid marker (got {auth_manifest_marker:#010x}, \
         expected {AUTH_MANIFEST_MARKER:#010x}). Ensure the auth-manifest path points at the \
         authorization manifest (as produced by the auth-manifest app) and not the fw image.",
    );

    let mut manifest_slice = [0u8; SetAuthManifestReq::MAX_MAN_SIZE];
    manifest_slice[..auth_manifest.len()].copy_from_slice(auth_manifest);
    let mut set_auth_manifest_cmd = MailboxReq::SetAuthManifest(SetAuthManifestReq {
        hdr: MailboxReqHeader { chksum: 0 },
        manifest_size: auth_manifest.len() as u32,
        manifest: manifest_slice,
    });
    set_auth_manifest_cmd.populate_chksum().unwrap();
    model.mailbox_execute(
        u32::from(CommandId::SET_AUTH_MANIFEST),
        set_auth_manifest_cmd.as_bytes().unwrap(),
    )
}

/// Read a Caliptra firmware image bundle and an authorization manifest from
/// disk, then run [`boot_and_set_auth_manifest`].
pub fn boot_and_set_auth_manifest_from_files(
    fw_image_path: impl AsRef<Path>,
    auth_manifest_path: impl AsRef<Path>,
    lms_verify: bool,
    expected_err: Option<CaliptraError>,
) {
    let fw_image_path = fw_image_path.as_ref();
    let auth_manifest_path = auth_manifest_path.as_ref();

    let fw_image = fs::read(fw_image_path)
        .unwrap_or_else(|e| panic!("failed to read fw image {fw_image_path:?}: {e}"));
    let auth_manifest = fs::read(auth_manifest_path)
        .unwrap_or_else(|e| panic!("failed to read auth manifest {auth_manifest_path:?}: {e}"));

    boot_and_set_auth_manifest(&fw_image, &auth_manifest, lms_verify, expected_err);
}

/// Build (and sign) a Caliptra firmware image bundle with the given options and
/// return its serialized bytes, ready to write to disk / inject into the model.
fn build_fw_image(image_options: ImageOptions) -> Vec<u8> {
    caliptra_builder::build_and_sign_image(&FMC_WITH_UART, &APP_WITH_UART, image_options)
        .unwrap()
        .to_bytes()
        .unwrap()
}

/// Write a firmware image and manifest to disk under a unique tag, then load
/// them back and run the key check. Round-tripping through disk exercises the
/// exact same path a user's own binaries would take.
fn write_to_disk_and_run(
    tag: &str,
    fw_image: &[u8],
    auth_manifest: &AuthorizationManifest,
    lms_verify: bool,
    expected_err: Option<CaliptraError>,
) {
    let dir = std::env::temp_dir();
    let fw_path = dir.join(format!("caliptra_test_fw_image_{tag}.bin"));
    let man_path = dir.join(format!("caliptra_test_auth_manifest_{tag}.bin"));

    fs::write(&fw_path, fw_image).unwrap();
    fs::write(&man_path, auth_manifest.as_bytes()).unwrap();

    boot_and_set_auth_manifest_from_files(&fw_path, &man_path, lms_verify, expected_err);
}

/// Inject a user-supplied Caliptra firmware image and authorization manifest
/// from disk.
///
/// This test is a no-op unless both file-path env vars are set, so it is safe
/// to keep in the normal suite. To run it against your own binaries:
///
/// ```text
/// CPTRA_FW_IMAGE_PATH=/path/to/caliptra_fw_image.bin \
/// CPTRA_AUTH_MANIFEST_PATH=/path/to/auth_manifest.bin \
/// cargo test -p caliptra-runtime --test runtime_integration_tests \
///     test_auth_manifest_from_disk -- --nocapture
/// ```
///
/// Optional env vars:
///   * `CPTRA_AUTH_MANIFEST_LMS`   - if set, boot with LMS verification enabled.
///   * `CPTRA_EXPECT_KEY_MISMATCH` - `vendor` | `owner` | `vendor-lms` | `owner-lms`
///       to assert that specific signature-invalid error is returned. If unset,
///       the command is expected to succeed (keys match).
#[test]
fn test_auth_manifest_from_disk() {
    let (Ok(fw_path), Ok(man_path)) = (
        std::env::var("CPTRA_FW_IMAGE_PATH"),
        std::env::var("CPTRA_AUTH_MANIFEST_PATH"),
    ) else {
        eprintln!(
            "skipping test_auth_manifest_from_disk: set CPTRA_FW_IMAGE_PATH and \
             CPTRA_AUTH_MANIFEST_PATH to inject your own binaries"
        );
        return;
    };

    let lms_verify = std::env::var_os("CPTRA_AUTH_MANIFEST_LMS").is_some();
    let expected_err = match std::env::var("CPTRA_EXPECT_KEY_MISMATCH").ok().as_deref() {
        Some("vendor") => Some(CaliptraError::RUNTIME_AUTH_MANIFEST_VENDOR_ECC_SIGNATURE_INVALID),
        Some("owner") => Some(CaliptraError::RUNTIME_AUTH_MANIFEST_OWNER_ECC_SIGNATURE_INVALID),
        Some("vendor-lms") => {
            Some(CaliptraError::RUNTIME_AUTH_MANIFEST_VENDOR_LMS_SIGNATURE_INVALID)
        }
        Some("owner-lms") => Some(CaliptraError::RUNTIME_AUTH_MANIFEST_OWNER_LMS_SIGNATURE_INVALID),
        None => None,
        Some(other) => panic!(
            "unknown CPTRA_EXPECT_KEY_MISMATCH value {other:?}; \
             expected one of: vendor, owner, vendor-lms, owner-lms"
        ),
    };

    boot_and_set_auth_manifest_from_files(fw_path, man_path, lms_verify, expected_err);
}

/// Positive control: the auth manifest's vendor/owner FW-signing keys match the
/// keys in the Caliptra fw image, so `SET_AUTH_MANIFEST` succeeds (both the ECC
/// and LMS paths, since `lms_verify` is enabled).
#[test]
fn test_auth_manifest_matching_keys_from_disk() {
    let fw_image = build_fw_image(ImageOptions {
        vendor_config: VENDOR_CONFIG_KEY_0,
        owner_config: Some(OWNER_CONFIG),
        ..Default::default()
    });
    let auth_manifest = create_auth_manifest(AuthManifestFlags::VENDOR_SIGNATURE_REQUIRED);

    write_to_disk_and_run("matching", &fw_image, &auth_manifest, true, None);
}

/// Vendor key mismatch: the manifest's vendor public keys are signed with a
/// vendor key (idx 2) that is not the fw image's active vendor key (idx 0), so
/// vendor-key verification fails. Vendor keys are checked before owner keys.
#[test]
fn test_auth_manifest_vendor_key_mismatch_from_disk() {
    let fw_image = build_fw_image(ImageOptions {
        vendor_config: VENDOR_CONFIG_KEY_0,
        owner_config: Some(OWNER_CONFIG),
        ..Default::default()
    });
    let auth_manifest = create_auth_manifest_wrong_key(AuthManifestFlags::VENDOR_SIGNATURE_REQUIRED);

    write_to_disk_and_run(
        "vendor_mismatch",
        &fw_image,
        &auth_manifest,
        false,
        Some(CaliptraError::RUNTIME_AUTH_MANIFEST_VENDOR_ECC_SIGNATURE_INVALID),
    );
}

/// Owner key mismatch: the manifest's vendor FW key matches the fw image, but
/// the owner public keys are signed with a key that is not the fw image's owner
/// key, so owner-key verification fails.
#[test]
fn test_auth_manifest_owner_key_mismatch_from_disk() {
    let fw_image = build_fw_image(ImageOptions {
        vendor_config: VENDOR_CONFIG_KEY_0,
        owner_config: Some(OWNER_CONFIG),
        ..Default::default()
    });
    let auth_manifest = create_auth_manifest_with_key_configs(
        AuthManifestFlags::VENDOR_SIGNATURE_REQUIRED,
        // vendor FW key matches the fw image's active vendor key (idx 0).
        auth_manifest_key_config(
            VENDOR_ECC_KEY_0_PUBLIC,
            VENDOR_ECC_KEY_0_PRIVATE,
            VENDOR_LMS_KEY_0_PUBLIC,
            VENDOR_LMS_KEY_0_PRIVATE,
        ),
        auth_manifest_key_config(
            VENDOR_ECC_KEY_1_PUBLIC,
            VENDOR_ECC_KEY_1_PRIVATE,
            VENDOR_LMS_KEY_1_PUBLIC,
            VENDOR_LMS_KEY_1_PRIVATE,
        ),
        // owner FW key does NOT match the fw image's owner key -> mismatch.
        auth_manifest_key_config(
            VENDOR_ECC_KEY_3_PUBLIC,
            VENDOR_ECC_KEY_3_PRIVATE,
            VENDOR_LMS_KEY_3_PUBLIC,
            VENDOR_LMS_KEY_3_PRIVATE,
        ),
        auth_manifest_key_config(
            OWNER_ECC_KEY_PUBLIC,
            OWNER_ECC_KEY_PRIVATE,
            OWNER_LMS_KEY_PUBLIC,
            OWNER_LMS_KEY_PRIVATE,
        ),
    );

    write_to_disk_and_run(
        "owner_mismatch",
        &fw_image,
        &auth_manifest,
        false,
        Some(CaliptraError::RUNTIME_AUTH_MANIFEST_OWNER_ECC_SIGNATURE_INVALID),
    );
}

/// Firmware-image-side mismatch: inject a *different* Caliptra fw image whose
/// active vendor key is idx 1, while the (default) auth manifest is signed with
/// the idx-0 vendor key. The active fw-image vendor key no longer matches, so
/// verification fails. This demonstrates injecting a custom fw image.
#[test]
fn test_auth_manifest_fw_image_vendor_idx_mismatch_from_disk() {
    let fw_image = build_fw_image(ImageOptions {
        vendor_config: VENDOR_CONFIG_KEY_1,
        owner_config: Some(OWNER_CONFIG),
        ..Default::default()
    });
    // Default manifest signs its vendor keys with vendor key idx 0.
    let auth_manifest = create_auth_manifest(AuthManifestFlags::VENDOR_SIGNATURE_REQUIRED);

    write_to_disk_and_run(
        "fw_vendor_idx_mismatch",
        &fw_image,
        &auth_manifest,
        false,
        Some(CaliptraError::RUNTIME_AUTH_MANIFEST_VENDOR_ECC_SIGNATURE_INVALID),
    );
}

/// Companion positive control for the previous test: when the fw image's active
/// vendor key is idx 1 *and* the manifest is signed with the idx-1 vendor key,
/// verification succeeds.
#[test]
fn test_auth_manifest_fw_image_vendor_idx_match_from_disk() {
    let fw_image = build_fw_image(ImageOptions {
        vendor_config: VENDOR_CONFIG_KEY_1,
        owner_config: Some(OWNER_CONFIG),
        ..Default::default()
    });
    let auth_manifest = create_auth_manifest_with_key_configs(
        AuthManifestFlags::VENDOR_SIGNATURE_REQUIRED,
        // vendor FW key matches the fw image's active vendor key (idx 1).
        auth_manifest_key_config(
            VENDOR_ECC_KEY_1_PUBLIC,
            VENDOR_ECC_KEY_1_PRIVATE,
            VENDOR_LMS_KEY_1_PUBLIC,
            VENDOR_LMS_KEY_1_PRIVATE,
        ),
        auth_manifest_key_config(
            VENDOR_ECC_KEY_2_PUBLIC,
            VENDOR_ECC_KEY_2_PRIVATE,
            VENDOR_LMS_KEY_2_PUBLIC,
            VENDOR_LMS_KEY_2_PRIVATE,
        ),
        auth_manifest_key_config(
            OWNER_ECC_KEY_PUBLIC,
            OWNER_ECC_KEY_PRIVATE,
            OWNER_LMS_KEY_PUBLIC,
            OWNER_LMS_KEY_PRIVATE,
        ),
        auth_manifest_key_config(
            OWNER_ECC_KEY_PUBLIC,
            OWNER_ECC_KEY_PRIVATE,
            OWNER_LMS_KEY_PUBLIC,
            OWNER_LMS_KEY_PRIVATE,
        ),
    );

    write_to_disk_and_run("fw_vendor_idx_match", &fw_image, &auth_manifest, false, None);
}

// ---------------------------------------------------------------------------
// Host-side ECC signature consistency checker
//
// Independently verifies (on the host, no emulator/ROM) that the vendor and
// owner ECDSA-384 signatures embedded in a Caliptra fw image are valid
// signatures by the vendor/owner public keys embedded in the SAME image, over
// the exact ranges caliptra ROM signs:
//   * vendor message = SHA384(header[0 .. offset_of(owner_data)])   (excludes owner_data)
//   * owner  message = SHA384(header[0 .. end])
//
// It tries a matrix of byte-order transforms on the scalars and reports which
// (if any) verifies. This isolates HSM signing-pipeline bugs: a good image
// verifies under the canonical caliptra word order; an image whose signature
// was produced by a different key than the embedded public key (or whose bytes
// are otherwise mangled) verifies under none.
// ---------------------------------------------------------------------------

/// `offset_of!(ImageHeader, owner_data)` — the vendor signature covers the
/// header up to (but not including) `owner_data`. Guarded by an assert on the
/// header size so it fails loudly if the layout ever changes.
const VENDOR_HEADER_LEN: usize = 0x74;

/// Byte-order transforms applied to a 48-byte scalar as it sits in the image.
#[derive(Clone, Copy)]
pub enum Xf {
    /// Bytes exactly as stored (native little-endian words).
    AsStored,
    /// Reverse every 4-byte word — yields caliptra's canonical big-endian scalar.
    Flip4,
    /// Full 48-byte reverse.
    Rev,
}

impl Xf {
    fn name(self) -> &'static str {
        match self {
            Xf::AsStored => "as-stored",
            Xf::Flip4 => "flip4(canonical)",
            Xf::Rev => "rev48",
        }
    }
    fn apply(self, stored: &[u8; 48]) -> [u8; 48] {
        let mut out = *stored;
        match self {
            Xf::AsStored => {}
            Xf::Flip4 => {
                for w in out.chunks_exact_mut(4) {
                    w.reverse();
                }
            }
            Xf::Rev => out.reverse(),
        }
        out
    }
}

const XFS: [Xf; 3] = [Xf::AsStored, Xf::Flip4, Xf::Rev];

/// The 48 stored bytes of a `[u32; 12]` scalar, in image (little-endian word) order.
fn scalar_stored_bytes(words: &[u32; 12]) -> [u8; 48] {
    let mut out = [0u8; 48];
    out.copy_from_slice(words.as_bytes());
    out
}

fn ecdsa384_verify(x: &[u8], y: &[u8], r: &[u8], s: &[u8], digest: &[u8; 48]) -> bool {
    let group = match EcGroup::from_curve_name(Nid::SECP384R1) {
        Ok(g) => g,
        Err(_) => return false,
    };
    let (Ok(bx), Ok(by), Ok(br), Ok(bs)) = (
        BigNum::from_slice(x),
        BigNum::from_slice(y),
        BigNum::from_slice(r),
        BigNum::from_slice(s),
    ) else {
        return false;
    };
    let Ok(key) = EcKey::from_public_key_affine_coordinates(&group, &bx, &by) else {
        return false;
    };
    let Ok(sig) = EcdsaSig::from_private_components(br, bs) else {
        return false;
    };
    sig.verify(digest, &key).unwrap_or(false)
}

/// Returns the (key_xf, sig_xf, swapped_rs) combos under which `sig` verifies
/// against `pub_key` over `digest`. Empty => the signature does not correspond
/// to this public key over this message under any byte order.
fn check_ecc_consistency(
    role: &str,
    pub_key: &ImageEccPubKey,
    sig: &ImageEccSignature,
    digest: &[u8; 48],
) -> Vec<(Xf, Xf, bool)> {
    let x = scalar_stored_bytes(&pub_key.x);
    let y = scalar_stored_bytes(&pub_key.y);
    let r = scalar_stored_bytes(&sig.r);
    let s = scalar_stored_bytes(&sig.s);

    let mut hits = Vec::new();
    for kxf in XFS {
        let (kx, ky) = (kxf.apply(&x), kxf.apply(&y));
        for sxf in XFS {
            for swapped in [false, true] {
                let (ra, sb) = if swapped { (&s, &r) } else { (&r, &s) };
                if ecdsa384_verify(&kx, &ky, &sxf.apply(ra), &sxf.apply(sb), digest) {
                    hits.push((kxf, sxf, swapped));
                }
            }
        }
    }

    println!("  [{role}] pubkey.x[..8]={:02x?} sig.r[..8]={:02x?}", &x[..8], &r[..8]);
    if hits.is_empty() {
        println!(
            "  [{role}] RESULT: NO byte-order verifies -> signature was NOT produced by the \
             embedded {role} public key (key-pairing mismatch), or bytes are otherwise mangled."
        );
    } else {
        for (k, s, sw) in &hits {
            let canonical = matches!((k, s, sw), (Xf::Flip4, Xf::Flip4, false));
            println!(
                "  [{role}] VERIFIES: key={} sig={} swap_rs={sw}{}",
                k.name(),
                s.name(),
                if canonical { "  (canonical - matches caliptra ROM)" } else { "" },
            );
        }
    }
    hits
}

/// Independently check a Caliptra fw image's embedded vendor/owner ECC
/// signatures against its embedded public keys, honoring the 16-byte legacy
/// header. Returns (vendor_hits, owner_hits).
pub fn check_image_ecc_consistency(fw_image: &[u8]) -> (Vec<(Xf, Xf, bool)>, Vec<(Xf, Xf, bool)>) {
    // Honor the 16-byte 0x5ABEBEE5 legacy header if present.
    let fw_image: &[u8] = if ImageManifest::read_from_prefix(fw_image)
        .is_ok_and(|(m, _)| m.marker == MANIFEST_MARKER)
    {
        fw_image
    } else {
        fw_image.get(16..).unwrap_or(&[])
    };

    let (manifest, _) = ImageManifest::read_from_prefix(fw_image)
        .expect("firmware image is too small / not a Caliptra image bundle");
    assert_eq!(manifest.marker, MANIFEST_MARKER, "missing CMAN marker");
    assert_eq!(
        core::mem::size_of::<caliptra_image_types::ImageHeader>(),
        156,
        "ImageHeader layout changed; update VENDOR_HEADER_LEN"
    );

    let header = manifest.header.as_bytes();
    let vendor_digest = sha384(&header[..VENDOR_HEADER_LEN]);
    let owner_digest = sha384(header);

    let vidx = manifest.preamble.vendor_ecc_pub_key_idx as usize;
    println!("  vendor_ecc_pub_key_idx = {vidx}");
    let vendor_pk = &manifest.preamble.vendor_pub_keys.ecc_pub_keys[vidx];
    let vendor_hits =
        check_ecc_consistency("vendor", vendor_pk, &manifest.preamble.vendor_sigs.ecc_sig, &vendor_digest);
    let owner_hits = check_ecc_consistency(
        "owner",
        &manifest.preamble.owner_pub_keys.ecc_pub_key,
        &manifest.preamble.owner_sigs.ecc_sig,
        &owner_digest,
    );
    (vendor_hits, owner_hits)
}

/// Host-side (no emulator) consistency check of a Caliptra fw image's embedded
/// vendor/owner ECC signatures vs its embedded public keys.
///
/// ```text
/// CPTRA_FW_IMAGE_PATH=/path/to/caliptra-image.bin \
/// cargo test -p caliptra-runtime --test runtime_integration_tests \
///     test_caliptra_image_ecc_consistency_from_disk -- --nocapture
/// ```
///
/// Optional: set `CPTRA_EXPECT_IMAGE_INCONSISTENT` to assert the image is
/// inconsistent (no byte-order verifies) — useful as a regression for a known
/// bad HSM-signing output. Otherwise the image is expected to verify under the
/// canonical caliptra byte order.
#[test]
fn test_caliptra_image_ecc_consistency_from_disk() {
    let Ok(fw_path) = std::env::var("CPTRA_FW_IMAGE_PATH") else {
        eprintln!(
            "skipping test_caliptra_image_ecc_consistency_from_disk: set CPTRA_FW_IMAGE_PATH \
             to a Caliptra fw image bundle"
        );
        return;
    };
    let fw_image = fs::read(&fw_path).unwrap_or_else(|e| panic!("failed to read {fw_path}: {e}"));
    println!("### {fw_path}");
    let (vendor_hits, owner_hits) = check_image_ecc_consistency(&fw_image);

    let expect_inconsistent = std::env::var_os("CPTRA_EXPECT_IMAGE_INCONSISTENT").is_some();
    let canonical = |hits: &[(Xf, Xf, bool)]| {
        hits.iter()
            .any(|c| matches!(c, (Xf::Flip4, Xf::Flip4, false)))
    };
    if expect_inconsistent {
        assert!(
            vendor_hits.is_empty() && owner_hits.is_empty(),
            "expected an inconsistent image, but a byte-order verified"
        );
    } else {
        assert!(
            canonical(&vendor_hits),
            "vendor ECC signature does not verify against the embedded vendor key under the \
             canonical caliptra byte order (see report above)"
        );
        assert!(
            canonical(&owner_hits),
            "owner ECC signature does not verify against the embedded owner key under the \
             canonical caliptra byte order (see report above)"
        );
    }
}

// ---------------------------------------------------------------------------
// AUTHORIZE_AND_STASH: validate real firmware images against the manifest IMC
// ---------------------------------------------------------------------------

fn hex48(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn auth_result_str(r: u32) -> &'static str {
    match r {
        IMAGE_AUTHORIZED => "IMAGE_AUTHORIZED",
        IMAGE_HASH_MISMATCH => "IMAGE_HASH_MISMATCH",
        IMAGE_NOT_AUTHORIZED => "IMAGE_NOT_AUTHORIZED",
        _ => "UNKNOWN",
    }
}

/// fw_id whose image is hashed with 16 zero bytes prepended, matching the
/// provisioning tool (commons/flash_consts.py: `SECMC_IMAGE_ID = 1`).
const SECMC_IMAGE_ID: u32 = 1;

/// Compute an IMC image digest the way the provisioning tool's `caliptra_auth.py`
/// (`MetadataEntry.from_config`, lines 52-64) does:
///   * for the SECMC image (`fw_id == SECMC_IMAGE_ID`) prepend 16 zero bytes,
///   * then, if an SVN is given, append it as 4 little-endian bytes,
///   * then SHA-384 the result.
fn imc_digest(fw_id: u32, file: &[u8], svn: Option<u32>) -> [u8; 48] {
    let mut buf: Vec<u8> = Vec::with_capacity(16 + file.len() + 4);
    if fw_id == SECMC_IMAGE_ID {
        buf.extend_from_slice(&[0u8; 16]);
    }
    buf.extend_from_slice(file);
    if let Some(svn) = svn {
        buf.extend_from_slice(&svn.to_le_bytes());
    }
    sha384(&buf)
}

/// After loading the auth manifest, validate that user-supplied firmware images
/// match the digests recorded in the manifest's Image Metadata Collection (IMC),
/// via `AUTHORIZE_AND_STASH`.
///
/// ```text
/// CPTRA_FW_IMAGE_PATH=/path/to/caliptra-image.bin \
/// CPTRA_AUTH_MANIFEST_PATH=/path/to/auth-manifest.bin \
/// CPTRA_IMAGES=/path/to/img0.bin@1:/path/to/secmc.ebin@1:/path/to/img2.bin@1100 \
/// cargo test -p caliptra-runtime --test runtime_integration_tests \
///     test_authorize_and_stash_from_disk -- --nocapture
/// ```
///
/// `CPTRA_IMAGES` is a `:`-separated list given in the SAME order as the IMC
/// entries: entry `i` is `path[i]`, optionally suffixed with `@<svn>`. Each image
/// is hashed exactly as the provisioning tool records it in the IMC
/// (`caliptra_auth.py` lines 52-64): the SECMC image (`fw_id == 1`) gets 16 zero
/// bytes prepended, then the SVN (if given) is appended as 4 little-endian bytes,
/// then SHA-384. The digest is sent as the measurement (`source = InRequest`) via
/// `AUTHORIZE_AND_STASH`, and the test asserts every image is `IMAGE_AUTHORIZED`.
/// Optional `CPTRA_AUTH_MANIFEST_LMS` boots with LMS on.
///
/// If a computed digest doesn't match its IMC entry you'll get
/// `IMAGE_HASH_MISMATCH`, and the printed computed-vs-IMC digests will show it
/// (e.g. a wrong/missing `@svn`, or the wrong image for that slot).
#[test]
fn test_authorize_and_stash_from_disk() {
    let (Ok(fw_path), Ok(man_path)) = (
        std::env::var("CPTRA_FW_IMAGE_PATH"),
        std::env::var("CPTRA_AUTH_MANIFEST_PATH"),
    ) else {
        eprintln!(
            "skipping test_authorize_and_stash_from_disk: set CPTRA_FW_IMAGE_PATH and \
             CPTRA_AUTH_MANIFEST_PATH"
        );
        return;
    };
    let Ok(images) = std::env::var("CPTRA_IMAGES") else {
        eprintln!(
            "skipping test_authorize_and_stash_from_disk: set CPTRA_IMAGES to a ':'-separated \
             list of firmware image paths, in the same order as the IMC entries"
        );
        return;
    };
    // Each spec is "path" or "path@svn"; order matches the IMC entries.
    let image_specs: Vec<&str> = images.split(':').filter(|s| !s.is_empty()).collect();
    let lms_verify = std::env::var_os("CPTRA_AUTH_MANIFEST_LMS").is_some();

    let fw_image = fs::read(&fw_path).unwrap_or_else(|e| panic!("failed to read {fw_path}: {e}"));
    let auth_manifest =
        fs::read(&man_path).unwrap_or_else(|e| panic!("failed to read {man_path}: {e}"));

    // Parse the IMC entries (in manifest order) so we can pair each provided
    // image with the matching fw_id/digest.
    let (manifest, _) = AuthorizationManifest::read_from_prefix(auth_manifest.as_slice())
        .expect("auth manifest is too small / not an AuthorizationManifest");
    let entry_count = manifest.image_metadata_col.entry_count as usize;
    let entries = &manifest.image_metadata_col.image_metadata_list[..entry_count];
    println!("IMC has {entry_count} entries; validating {} image(s)", image_specs.len());
    assert!(
        image_specs.len() <= entry_count,
        "provided {} images but the IMC has only {entry_count} entries",
        image_specs.len()
    );

    let mut model = boot_and_set_auth_manifest_ok(&fw_image, &auth_manifest, lms_verify);

    // AUTHORIZE_AND_STASH is a PL0-restricted command: issue it with the image's
    // PL0 PAUSER so the runtime treats the caller as PL0 (otherwise it fails with
    // RUNTIME_INCORRECT_PAUSER_PRIVILEGE_LEVEL). boot_model_with_fw_image already
    // registered this PAUSER as valid for the mailbox.
    if let Some(pl0) = fw_image_pl0_pauser(&fw_image) {
        println!("setting APB PAUSER to PL0 pauser {pl0:#010x} for AUTHORIZE_AND_STASH");
        model.set_apb_pauser(pl0);
    }

    for (i, spec) in image_specs.iter().enumerate() {
        let entry = &entries[i];
        // Split an optional "@<svn>" suffix (only when it parses as a u32, so
        // paths containing '@' still work if no numeric svn follows).
        let (path, svn) = match spec.rsplit_once('@') {
            Some((p, s)) => match s.parse::<u32>() {
                Ok(v) => (p, Some(v)),
                Err(_) => (*spec, None),
            },
            None => (*spec, None),
        };
        let img = fs::read(path).unwrap_or_else(|e| panic!("failed to read image {path}: {e}"));
        let measurement = imc_digest(entry.fw_id, &img, svn);
        let flags = ImageMetadataFlags(entry.flags);

        println!(
            "\nimage[{i}] {path} ({} bytes)\n  fw_id={} svn={svn:?} secmc_pad={} \
             ignore_auth_check={} image_source={}\n  computed sha384 = {}\n  IMC entry digest= {}",
            img.len(),
            entry.fw_id,
            entry.fw_id == SECMC_IMAGE_ID,
            flags.ignore_auth_check(),
            flags.image_source(),
            hex48(&measurement),
            hex48(&entry.digest),
        );

        let mut cmd = MailboxReq::AuthorizeAndStash(AuthorizeAndStashReq {
            hdr: MailboxReqHeader { chksum: 0 },
            fw_id: entry.fw_id.to_le_bytes(),
            measurement,
            source: ImageHashSource::InRequest as u32,
            flags: 0, // do not skip stashing
            ..Default::default()
        });
        cmd.populate_chksum().unwrap();

        let resp = model
            .mailbox_execute(
                u32::from(CommandId::AUTHORIZE_AND_STASH),
                cmd.as_bytes().unwrap(),
            )
            .unwrap()
            .expect("AUTHORIZE_AND_STASH should return a response");
        let resp = AuthorizeAndStashResp::read_from_bytes(resp.as_slice()).unwrap();
        println!("  -> {}", auth_result_str(resp.auth_req_result));

        assert_eq!(
            resp.auth_req_result, IMAGE_AUTHORIZED,
            "image {path} (fw_id {}) was not authorized against the IMC: got {} \
             (computed sha384 {} vs IMC digest {})",
            entry.fw_id,
            auth_result_str(resp.auth_req_result),
            hex48(&measurement),
            hex48(&entry.digest),
        );
    }
}

// ---------------------------------------------------------------------------
// test_axiado_flash_image: extract everything from a single Axiado FLASH*.bin
// ---------------------------------------------------------------------------
//
// Flash layout (from the provisioning tool's commons/flash_consts.py and
// tools/flash_ultra.py):
//   [0x00000, 0x01000)  PBCB (0xFF fill)
//   [0x01000, 0x41000)  Caliptra image bundle (16-byte legacy header + CMAN)
//   [0x41000, 0x51000)  AX SOC manifest region:
//       [0x41000, 0x47000)  soc_manifest  = the authorization manifest (NMTA)
//       [0x47000, 0x49000)  ax_image_map  = AXImageMapEntry[] (64 bytes each)
//       [0x49000, 0x4A000)  ax_device_metadata
//   [0x51000, ...)      dynamic partition = the firmware images (each already
//                       includes the SECMC 16-byte pad + 4-byte LE SVN, exactly
//                       as hashed for the IMC), located via the image map.

/// `sizeof(ax_image_map_entry_t)` from flash_map_ultra.h — a fixed C struct
/// (image_id, offset, size, load_address, entry_point, svn, max_size,
/// reserved[28]), so it's a constant, not one of the `#define`d offsets.
const AX_IMAGE_MAP_ENTRY_SIZE: usize = 64;

/// Flash region offsets/sizes. Defaults match the provisioning tool
/// (commons/flash_consts.py / c_src/flash_map_ultra.h); can be overridden by
/// parsing a `flash_map_ultra.h` (see [`FlashLayout::from_header`]).
#[derive(Debug, Clone, Copy)]
struct FlashLayout {
    caliptra_base: usize,
    mnfst_base: usize,
    cali_mnfst_max_size: usize,
    imap_max_size: usize,
    imap_entries_max: usize,
    dynamic_base: usize,
}

impl Default for FlashLayout {
    fn default() -> Self {
        Self {
            caliptra_base: 0x1000,
            mnfst_base: 0x41000,
            cali_mnfst_max_size: 0x6000,
            imap_max_size: 0x2000,
            imap_entries_max: 127,
            dynamic_base: 0x51000,
        }
    }
}

impl FlashLayout {
    /// The AX image map immediately follows the caliptra manifest inside the SOC
    /// manifest region (`offsetof(ax_soc_manifest_layout_t, image_map)`).
    fn imap_base(&self) -> usize {
        self.mnfst_base + self.cali_mnfst_max_size
    }

    /// Override the defaults with values parsed from a `flash_map_ultra.h`.
    /// Only the offsets this test needs are read; anything missing keeps its
    /// default. Non-literal `#define`s (e.g. `MEM_REGION_SIZE(...)`) are ignored.
    fn from_header(path: &str) -> Self {
        let text = fs::read_to_string(path)
            .unwrap_or_else(|e| panic!("failed to read flash map header {path}: {e}"));
        let mut defs: std::collections::HashMap<String, u64> = std::collections::HashMap::new();
        for line in text.lines() {
            let rest = match line.trim().strip_prefix("#define") {
                Some(r) => r.trim(),
                None => continue,
            };
            let mut it = rest.splitn(2, char::is_whitespace);
            if let (Some(name), Some(val)) = (it.next(), it.next()) {
                if let Some(v) = parse_c_uint(val) {
                    defs.insert(name.to_string(), v);
                }
            }
        }
        let mut l = FlashLayout::default();
        let mut set = |field: &mut usize, key: &str| {
            if let Some(v) = defs.get(key) {
                *field = *v as usize;
            }
        };
        set(&mut l.caliptra_base, "CALIPTRA_IMG_BUNDLE_BASE");
        set(&mut l.mnfst_base, "AX_SOC_MNFST_BASE");
        set(&mut l.cali_mnfst_max_size, "AX_SOC_CALI_MNFST_MAX_SIZE");
        set(&mut l.imap_max_size, "AX_SOC_IMAP_MAX_SIZE");
        set(&mut l.imap_entries_max, "AX_SOC_IMAP_ENTRIES_MAX");
        set(&mut l.dynamic_base, "DYNAMIC_PARTITION_BASE");
        l
    }
}

/// Parse a simple C integer literal as used in flash_map_ultra.h: optional
/// surrounding parens, hex (`0x..`) or decimal, an optional `U`/`L` suffix, and
/// an optional trailing comment. Returns `None` for anything non-literal (e.g.
/// macro invocations like `MEM_REGION_SIZE(...)`).
fn parse_c_uint(val: &str) -> Option<u64> {
    let mut s = val;
    for marker in ["/*", "//"] {
        if let Some(idx) = s.find(marker) {
            s = &s[..idx];
        }
    }
    let s = s.trim();
    let s = s
        .strip_prefix('(')
        .map(|x| x.trim_end_matches(')'))
        .unwrap_or(s)
        .trim()
        .trim_end_matches(|c| matches!(c, 'U' | 'u' | 'L' | 'l'));
    if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        u64::from_str_radix(hex, 16).ok()
    } else {
        s.parse::<u64>().ok()
    }
}

/// One parsed `AXImageMapEntry` (only the fields we need).
struct FlashImageMapEntry {
    image_id: u32,
    offset: u32, // relative to the dynamic-partition base
    size: u32,   // length of the stored image bytes (incl. SECMC pad + SVN)
}

/// Extract the Caliptra fw image bundle from the flash: strip the 16-byte legacy
/// header and truncate to the exact bundle length (so FW_LOAD gets the right size
/// rather than the whole caliptra region).
fn extract_caliptra_image(flash: &[u8], layout: &FlashLayout) -> Vec<u8> {
    let region = flash
        .get(layout.caliptra_base..)
        .expect("flash is too small for the Caliptra image region");
    let cman = normalize_fw_image(region);
    let (m, _) =
        ImageManifest::read_from_prefix(cman).expect("Caliptra image manifest failed to parse");
    let end = ((m.fmc.offset + m.fmc.size).max(m.runtime.offset + m.runtime.size)) as usize;
    cman.get(..end)
        .expect("Caliptra image truncation out of bounds")
        .to_vec()
}

/// Extract the authorization manifest (the `cali_manifest` field at the SOC
/// manifest base). Its length is fixed at `size_of::<AuthorizationManifest>()`.
fn extract_auth_manifest(flash: &[u8], layout: &FlashLayout) -> Vec<u8> {
    let len = core::mem::size_of::<AuthorizationManifest>();
    flash
        .get(layout.mnfst_base..layout.mnfst_base + len)
        .expect("flash is too small for the auth manifest")
        .to_vec()
}

/// Parse the AX image map (array of `AX_IMAGE_MAP_ENTRY_SIZE`-byte entries at
/// `layout.imap_base()`), stopping at the first zero-size (padding) entry.
fn parse_ax_image_map(flash: &[u8], layout: &FlashLayout) -> Vec<FlashImageMapEntry> {
    let base = layout.imap_base();
    let map = flash
        .get(base..base + layout.imap_max_size)
        .expect("flash is too small for the AX image map");
    let mut entries = Vec::new();
    for i in 0..layout.imap_entries_max {
        let e = &map[i * AX_IMAGE_MAP_ENTRY_SIZE..(i + 1) * AX_IMAGE_MAP_ENTRY_SIZE];
        let rd = |o: usize| u32::from_le_bytes(e[o..o + 4].try_into().unwrap());
        // AXImageMapEntry: image_id(0), offset(4), size(8), load_addr(12), ...
        let size = rd(8);
        if size == 0 {
            break;
        }
        entries.push(FlashImageMapEntry {
            image_id: rd(0),
            offset: rd(4),
            size,
        });
    }
    entries
}

/// Extension of `test_auth_manifest_from_disk` that works from a single Axiado
/// flash image. Given `CPTRA_FLASH_IMAGE_PATH` pointing at a `FLASH*.bin`, this
/// extracts the Caliptra fw image, the authorization manifest, and the firmware
/// images (via the AX image map), then performs the same verifications:
///   1. boot the Caliptra fw image (ROM accepts it),
///   2. `SET_AUTH_MANIFEST` (auth manifest keys chain to the fw image keys),
///   3. `AUTHORIZE_AND_STASH` for every IMC-covered firmware image, asserting
///      each is `IMAGE_AUTHORIZED` (the extracted image bytes already include the
///      SECMC pad + SVN, so the measurement is a plain SHA-384 of them).
///
/// ```text
/// CPTRA_FLASH_IMAGE_PATH=/path/to/FLASH_A_<ts>.bin \
/// cargo test -p caliptra-runtime --test runtime_integration_tests \
///     test_axiado_flash_image -- --nocapture
/// ```
///
/// Flash offsets default to the built-in layout (commons/flash_consts.py /
/// c_src/flash_map_ultra.h). Set `CPTRA_FLASH_MAP_HEADER=/path/to/flash_map_ultra.h`
/// to derive them from that header instead. Optional `CPTRA_AUTH_MANIFEST_LMS`
/// boots with LMS verification.
#[test]
fn test_axiado_flash_image() {
    let Ok(flash_path) = std::env::var("CPTRA_FLASH_IMAGE_PATH") else {
        eprintln!(
            "skipping test_axiado_flash_image: set CPTRA_FLASH_IMAGE_PATH to an Axiado FLASH*.bin"
        );
        return;
    };
    let lms_verify = std::env::var_os("CPTRA_AUTH_MANIFEST_LMS").is_some();
    let flash =
        fs::read(&flash_path).unwrap_or_else(|e| panic!("failed to read {flash_path}: {e}"));

    // Flash offsets: derive from a flash_map_ultra.h if CPTRA_FLASH_MAP_HEADER is
    // set, else use the built-in defaults.
    let layout = match std::env::var("CPTRA_FLASH_MAP_HEADER") {
        Ok(p) => {
            let l = FlashLayout::from_header(&p);
            println!("flash layout from {p}: {l:?}");
            l
        }
        Err(_) => {
            let l = FlashLayout::default();
            println!("flash layout (built-in defaults): {l:?}");
            l
        }
    };

    let caliptra_image = extract_caliptra_image(&flash, &layout);
    let auth_manifest = extract_auth_manifest(&flash, &layout);
    let image_map = parse_ax_image_map(&flash, &layout);
    println!(
        "flash {} bytes -> caliptra image {} bytes, auth manifest {} bytes, {} image-map entries",
        flash.len(),
        caliptra_image.len(),
        auth_manifest.len(),
        image_map.len()
    );

    // Parse the IMC entries from the extracted auth manifest.
    let (manifest, _) = AuthorizationManifest::read_from_prefix(auth_manifest.as_slice())
        .expect("extracted auth manifest is not an AuthorizationManifest");
    let entry_count = manifest.image_metadata_col.entry_count as usize;
    let imc = &manifest.image_metadata_col.image_metadata_list[..entry_count];

    let mut model = boot_and_set_auth_manifest_ok(&caliptra_image, &auth_manifest, lms_verify);
    if let Some(pl0) = fw_image_pl0_pauser(&caliptra_image) {
        println!("setting APB PAUSER to PL0 pauser {pl0:#010x} for AUTHORIZE_AND_STASH");
        model.set_apb_pauser(pl0);
    }

    // Validate every IMC-covered firmware image found in the flash.
    for entry in imc {
        let flags = ImageMetadataFlags(entry.flags);
        let map_entry = image_map
            .iter()
            .find(|m| m.image_id == entry.fw_id)
            .unwrap_or_else(|| {
                panic!(
                    "IMC fw_id {} has no matching entry in the flash AX image map",
                    entry.fw_id
                )
            });
        let start = layout.dynamic_base + map_entry.offset as usize;
        let img = flash
            .get(start..start + map_entry.size as usize)
            .unwrap_or_else(|| panic!("image for fw_id {} is out of flash bounds", entry.fw_id));
        // The stored bytes already include the SECMC pad + SVN, so the IMC
        // measurement is a plain SHA-384 of them.
        let measurement = sha384(img);

        println!(
            "\nfw_id={} (dynamic-partition offset {:#x}, {} bytes) ignore_auth_check={} \
             image_source={}\n  extracted sha384 = {}\n  IMC entry digest = {}",
            entry.fw_id,
            map_entry.offset,
            map_entry.size,
            flags.ignore_auth_check(),
            flags.image_source(),
            hex48(&measurement),
            hex48(&entry.digest),
        );

        let mut cmd = MailboxReq::AuthorizeAndStash(AuthorizeAndStashReq {
            hdr: MailboxReqHeader { chksum: 0 },
            fw_id: entry.fw_id.to_le_bytes(),
            measurement,
            source: ImageHashSource::InRequest as u32,
            flags: 0,
            ..Default::default()
        });
        cmd.populate_chksum().unwrap();

        let resp = model
            .mailbox_execute(
                u32::from(CommandId::AUTHORIZE_AND_STASH),
                cmd.as_bytes().unwrap(),
            )
            .unwrap()
            .expect("AUTHORIZE_AND_STASH should return a response");
        let resp = AuthorizeAndStashResp::read_from_bytes(resp.as_slice()).unwrap();
        println!("  -> {}", auth_result_str(resp.auth_req_result));

        assert_eq!(
            resp.auth_req_result, IMAGE_AUTHORIZED,
            "fw_id {} was not authorized against the IMC: got {} \
             (extracted sha384 {} vs IMC digest {})",
            entry.fw_id,
            auth_result_str(resp.auth_req_result),
            hex48(&measurement),
            hex48(&entry.digest),
        );
    }
}
