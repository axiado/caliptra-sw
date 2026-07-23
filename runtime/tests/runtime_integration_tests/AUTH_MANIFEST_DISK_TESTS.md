# Auth-manifest / flash-image disk-injection tests

These tests live in
[`test_auth_manifest_key_mismatch.rs`](test_auth_manifest_key_mismatch.rs) and
inject **real, already-signed** binaries into the Caliptra software emulator to
validate:

1. the authorization-manifest ⇄ Caliptra-fw-image **key** relationship
   (`SET_AUTH_MANIFEST`), and
2. that the actual **firmware images** match the digests recorded in the
   manifest's Image Metadata Collection / IMC (`AUTHORIZE_AND_STASH`).

They are **env-var driven** and **skip cleanly (pass, no-op) when their env vars
are unset**, so they are safe to keep in the normal suite. `cargo test` cannot
forward custom `--image` style flags (libtest owns the args after `--`), which
is why inputs are passed via environment variables.

All of them use the software emulator (`DefaultHwModel = ModelEmulated`) — no
RTL/verilator/FPGA required.

---

## Prerequisites (after cloning caliptra-sw)

- **`dpe` submodule** (required — it is a workspace member and dependency):
  ```bash
  # fresh clone
  git clone https://github.com/chipsalliance/caliptra-sw \
      --config submodule.recurse=true --recurse-submodules=dpe
  # or, if already cloned:
  git submodule update --init dpe
  ```
- **RTL submodule is NOT needed.** `hw/latest/rtl` / `hw/1.0/rtl` are only for
  verilated/FPGA models or regenerating the `caliptra-registers` crate (which is
  already committed). Skip them.
- **Rust toolchain**: pinned by `rust-toolchain.toml` (adds the
  `riscv32imc-unknown-none-elf` target); `rustup` installs it on first build.
  The tests build ROM/FMC/RT firmware at runtime via `caliptra-builder`.
- **OpenSSL (vendored)** build tools: a C compiler (`cc`, `make`) and `perl`.

---

## Quick reference

| Test | Purpose | Required env | Optional env |
|------|---------|--------------|--------------|
| `test_auth_manifest_from_disk` | Boot a fw image, `SET_AUTH_MANIFEST`; check the manifest's vendor/owner keys chain to the fw image's keys | `CPTRA_FW_IMAGE_PATH`, `CPTRA_AUTH_MANIFEST_PATH` | `CPTRA_AUTH_MANIFEST_LMS`, `CPTRA_EXPECT_KEY_MISMATCH` |
| `test_caliptra_image_ecc_consistency_from_disk` | Host-side only (no emulator): verify the fw image's embedded vendor/owner ECC signatures against its own embedded keys | `CPTRA_FW_IMAGE_PATH` | `CPTRA_EXPECT_IMAGE_INCONSISTENT` |
| `test_authorize_and_stash_from_disk` | After loading the manifest, validate individual firmware images against the IMC via `AUTHORIZE_AND_STASH` | `CPTRA_FW_IMAGE_PATH`, `CPTRA_AUTH_MANIFEST_PATH`, `CPTRA_IMAGES` | `CPTRA_AUTH_MANIFEST_LMS` |
| `test_axiado_flash_image` | Extract the caliptra image, manifest, **and** firmware images from a single Axiado `FLASH*.bin` and run the full chain | `CPTRA_FLASH_IMAGE_PATH` | `CPTRA_FLASH_MAP_HEADER`, `CPTRA_AUTH_MANIFEST_LMS` |

Run a single test with:
```bash
cargo test -p caliptra-runtime --test runtime_integration_tests <TEST_NAME> -- --nocapture
```

---

## `test_authorize_and_stash_from_disk`

Loads a Caliptra fw image + authorization manifest, boots the emulator, sends
`SET_AUTH_MANIFEST`, then for each firmware image you supply computes its
measurement and sends `AUTHORIZE_AND_STASH`, asserting `IMAGE_AUTHORIZED`.

**Environment:**

- `CPTRA_FW_IMAGE_PATH` — raw Caliptra fw image bundle (`.bin`). A 16-byte
  Axiado legacy header (`0x5ABEBEE5`) is auto-stripped if present.
- `CPTRA_AUTH_MANIFEST_PATH` — the authorization manifest (`.bin`, `NMTA`).
- `CPTRA_IMAGES` — a **`:`-separated** list of firmware image paths, **in the
  same order as the IMC entries** (`path[i]` ↔ IMC entry `[i]`). Each path may
  carry an optional `@<svn>` suffix.
- `CPTRA_AUTH_MANIFEST_LMS` — (optional) boot with LMS verification enabled.

**Digest recipe.** Each image's measurement is computed exactly as the
provisioning tool records it in the IMC (`caliptra_auth.py` lines 52-64):

```
buf = (16 zero bytes  if fw_id == 1 / SECMC)  ++  file_bytes  ++  (svn as 4-byte little-endian, if given)
measurement = SHA-384(buf)
```

So the SECMC image (`fw_id == 1`) is auto-prepended with 16 zero bytes, and the
SVN (from your `flash.yaml` metadata entry) is appended when you pass `@<svn>`.

**Example** (fw_ids 0, 1, 2, 5 with svns 1, 1, 1, 1100):
```bash
P=/path/to/provision/ws/artifacts
CPTRA_FW_IMAGE_PATH="$P/caliptra/caliptra-<ts>.bin" \
CPTRA_AUTH_MANIFEST_PATH="$P/caliptra_auth/caliptra-auth-<ts>.bin" \
CPTRA_IMAGES="/path/sbl.bin@1:/path/secmc.img.ebin@1:/path/sysmgr.bin@1:/path/u-boot.bin@1100" \
cargo test -p caliptra-runtime --test runtime_integration_tests \
    test_authorize_and_stash_from_disk -- --nocapture
```

Each image prints `fw_id`, `svn`, `secmc_pad`, `ignore_auth_check`,
`image_source`, the computed vs IMC digest, and the result. The test passes when
every image is `IMAGE_AUTHORIZED`. A mismatch prints the computed-vs-IMC digests
so you can see whether it's a wrong `@svn` or a stale image for that slot.

> Note: `AUTHORIZE_AND_STASH` is a **PL0**-restricted command. The harness reads
> the image's `pl0_pauser` (when the header opts into PL0 gating) and issues the
> command with that PAUSER; otherwise the runtime returns
> `RUNTIME_INCORRECT_PAUSER_PRIVILEGE_LEVEL`.

---

## `test_axiado_flash_image`

Same verifications as above but from a **single Axiado flash image** — it
extracts the caliptra fw image, the authorization manifest, and the firmware
images itself, using the offsets from the provisioning tool's flash layout
(`flash_ultra.py` / `flash_consts.py` / `flash_map_ultra.h`).

**Environment:**

- `CPTRA_FLASH_IMAGE_PATH` — an Axiado `FLASH*.bin` (e.g. `FLASH_A_<ts>.bin`).
- `CPTRA_FLASH_MAP_HEADER` — (optional) path to `flash_map_ultra.h`. If set, the
  region offsets are parsed from that header
  (`CALIPTRA_IMG_BUNDLE_BASE`, `AX_SOC_MNFST_BASE`, `AX_SOC_CALI_MNFST_MAX_SIZE`,
  `AX_SOC_IMAP_MAX_SIZE`, `AX_SOC_IMAP_ENTRIES_MAX`, `DYNAMIC_PARTITION_BASE`).
  If unset, built-in defaults matching `flash_consts.py` are used.
- `CPTRA_AUTH_MANIFEST_LMS` — (optional) boot with LMS verification enabled.

**What it extracts (default layout):**

| Region | Offset | Contents |
|--------|--------|----------|
| Caliptra image bundle | `0x1000` | 16-byte legacy header + `CMAN` bundle (truncated to the exact bundle length from the manifest TOC) |
| Auth manifest | `0x41000` | the `cali_manifest` field (`NMTA`), `size_of::<AuthorizationManifest>()` bytes |
| AX image map | `0x47000` | `AXImageMapEntry[]` (64 bytes each) → `{image_id, offset, size}` |
| Dynamic partition | `0x51000` | firmware images at `base + entry.offset`, `entry.size` bytes |

No `@svn` is needed here: the bytes stored in the dynamic partition **already
include** the SECMC 16-byte pad and the 4-byte SVN, so the measurement is a plain
`SHA-384` of the extracted bytes. Only the images the **IMC covers** are
validated (images present in the flash but not in the manifest are not
authorized by design).

**Example:**
```bash
CPTRA_FLASH_IMAGE_PATH=/path/to/provision/ws/artifacts/FLASH_A_<ts>.bin \
CPTRA_FLASH_MAP_HEADER=/path/to/provision/c_src/flash_map_ultra.h \
cargo test -p caliptra-runtime --test runtime_integration_tests \
    test_axiado_flash_image -- --nocapture
```

---

## `test_auth_manifest_from_disk` (key-relationship check)

Boots the fw image and sends `SET_AUTH_MANIFEST`.

- `CPTRA_FW_IMAGE_PATH`, `CPTRA_AUTH_MANIFEST_PATH` — required.
- `CPTRA_AUTH_MANIFEST_LMS` — (optional) LMS on.
- `CPTRA_EXPECT_KEY_MISMATCH` — (optional) assert a specific failure instead of
  success: `vendor`, `owner`, `vendor-lms`, or `owner-lms`. Unset ⇒ the manifest
  must be accepted (its vendor/owner "fw" keys match the fw image's keys).

```bash
CPTRA_FW_IMAGE_PATH=.../caliptra-<ts>.bin \
CPTRA_AUTH_MANIFEST_PATH=.../caliptra-auth-<ts>.bin \
cargo test -p caliptra-runtime --test runtime_integration_tests \
    test_auth_manifest_from_disk -- --nocapture
```

---

## `test_caliptra_image_ecc_consistency_from_disk` (host-side, no emulator)

Verifies a Caliptra fw image's embedded vendor/owner ECDSA-384 signatures
against its own embedded public keys, over the exact ranges ROM signs, trying a
matrix of byte-order transforms and reporting which verifies. Useful for
diagnosing HSM signing-pipeline issues (endianness / wrong-key) without booting.

- `CPTRA_FW_IMAGE_PATH` — required.
- `CPTRA_EXPECT_IMAGE_INCONSISTENT` — (optional) assert the image is
  inconsistent (no byte order verifies), e.g. as a regression for a known-bad
  signing output. Unset ⇒ the image must verify under the canonical byte order.

A standalone Python equivalent (with ECDSA public-key recovery) also exists in
the provisioning repo at `tools/caliptra_ecc_check.py`.

---

## Common gotchas

- **`ROM Fatal Error: 0x000B0001`** — the fw image doesn't start with the `CMAN`
  marker; the harness auto-strips a 16-byte legacy header, so this usually means
  the wrong file / a non-bundle format.
- **`0x000B000C` (`IMAGE_VERIFIER_ERR_VENDOR_ECC_SIGNATURE_INVALID`)** — ROM
  rejected the fw image's own signature (image/ROM version or signing mismatch);
  boot never reaches the manifest check. Use
  `test_caliptra_image_ecc_consistency_from_disk` to diagnose.
- **`0x000E0047` (`RUNTIME_AUTH_MANIFEST_VENDOR_ECC_SIGNATURE_INVALID`)** — the
  manifest's vendor "fw" key ≠ the fw image's active vendor key. The two must be
  the same key (likewise owner).
- **`0x000E0016` (`RUNTIME_INCORRECT_PAUSER_PRIVILEGE_LEVEL`)** — a PL0 command
  issued with the wrong PAUSER (handled automatically by the harness via the
  image's `pl0_pauser`).
- **`IMAGE_HASH_MISMATCH`** — the firmware image doesn't match its IMC digest:
  wrong `@svn`, wrong SECMC padding, or a stale image for that slot.
