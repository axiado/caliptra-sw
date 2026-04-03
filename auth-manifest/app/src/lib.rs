/*++

Licensed under the Apache-2.0 license.

File Name:

   lib.rs

Abstract:

    Library entry point for Caliptra Authorization Manifest utilities

--*/

pub mod config;

// Re-export commonly used types for consumers.
pub use config::AuthManifestKeyConfigFromFile;