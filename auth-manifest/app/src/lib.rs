/*++

Licensed under the Apache-2.0 license.

File Name:

   lib.rs

Abstract:

    Library entry point for Caliptra Authorization Manifest utilities

--*/

pub mod config;

// Re-export commonly used types for consumers.
pub use config::{
    AuthManifestConfigFromFile, AuthManifestKeyConfigFromFile, image_metadata_config_from_file,
    load_auth_man_config_from_file, optional_key_config_from_file,
};