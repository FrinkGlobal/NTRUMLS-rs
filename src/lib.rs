//! This crate implements the NTRUMLS library in Rust. It is an interface to the reference NTRUMLS
//! implementation. NTRUMLS is a modular latice signature based in NTRU, which avoids the security
//! issues of NTRUSign. More on NTRUMLS
//! [here](https://github.com/NTRUOpenSourceProject/NTRUMLS/raw/master/doc/NTRUMLS-preprint.pdf).
//!
//! NTRU is a faster encryption / decryption scheme, that uses latice based encryption to provide
//! quantum proof security. More on NTRUEncrypt [here](https://en.wikipedia.org/wiki/NTRUEncrypt).
//!
//! To use this library, you need to include this in your crate:
//!
//! ```
//! extern crate ntrumls;
//! ```
//!
//! # Examples
//!
//! To generate the keys that will be used during encryption / decryption, you have to use the
//! ```generate_keys()``` function. These keys must not be used in NTRUEncrypt nor in other
//! encryption schemes, since they are specifically generated for this purpose. Example:
//!
//! ```
//! use ntrumls::params::{ParamSet, XXX_20151024_743};
//!
//! let params = XXX_20151024_743;
//! let (private_key, public_key) = ntrumls::generate_keys(&params).unwrap();
//!
//! let mut message = b"Hello from NTRUMLS!";
//!
//! let signature = ntrumls::sign(&private_key, &public_key, message).unwrap();
//! assert!(ntrumls::verify(&signature, &public_key, message));
//! ```

// #![forbid(missing_docs, warnings)]
#![deny(deprecated, drop_with_repr_extern, improper_ctypes,
        non_shorthand_field_patterns, overflowing_literals, plugin_as_library,
        private_no_mangle_fns, private_no_mangle_statics, stable_features, unconditional_recursion,
        unknown_lints, unused, unused_allocation, unused_attributes,
        unused_comparisons, unused_features, unused_parens, while_true)]
#![warn(missing_docs, trivial_casts, trivial_numeric_casts, unused, unused_extern_crates,
        unused_import_braces, unused_qualifications, unused_results, variant_size_differences)]

extern crate libc;

pub mod params;
mod ffi;

use std::ptr;
use params::ParamSet;

/// Generates a public and private key pair
///
/// This function generates a public and private key pair to use when signing and verifying a
/// message. It needs the NTRUMLS parameter to use, and it will return an optional tuple, with the
/// private key in the first position and the public key in the second position. If something goes
/// wrong, ```None``` will be returned. Example:
///
/// ```
/// use ntrumls::params::{ParamSet, XXX_20151024_743};
///
/// let params = XXX_20151024_743;
/// let (private_key, public_key) = ntrumls::generate_keys(&params).unwrap();
///
/// ```
pub fn generate_keys(params: &ParamSet) -> Option<(PrivateKey, PublicKey)> {
    let (mut privkey_blob_len, mut pubkey_blob_len) = (0usize, 0usize);

    let result = unsafe {
        ffi::pq_gen_key(params,
                        &mut privkey_blob_len,
                        ptr::null_mut(),
                        &mut pubkey_blob_len,
                        ptr::null_mut())
    };
    if result != 0 {
        return None;
    }

    let mut privkey_blob = vec![0u8; privkey_blob_len];
    let mut pubkey_blob = vec![0u8; pubkey_blob_len];
    let result = unsafe {
        ffi::pq_gen_key(params,
                        &mut privkey_blob_len,
                        &mut privkey_blob[..][0],
                        &mut pubkey_blob_len,
                        &mut pubkey_blob[..][0])
    };

    if result != 0 {
        None
    } else {
        Some((PrivateKey::import(privkey_blob.as_slice()),
              PublicKey::import(pubkey_blob.as_slice())))
    }
}

/// Signs a message
///
/// This function signs a message using the public and private key pair. It will return an optional
/// boxed byte array, with the signed message. If something goes wrong, ```None``` will be
/// returned. Example:
///
/// ```
/// # use ntrumls::params::{ParamSet, XXX_20151024_743};
///
/// # let params = XXX_20151024_743;
/// # let (private_key, public_key) = ntrumls::generate_keys(&params).unwrap();
/// #
/// let mut message = b"Hello from NTRUMLS!";
/// let signature = ntrumls::sign(&private_key, &public_key, message).unwrap();
/// ```
pub fn sign(private_key: &PrivateKey, public_key: &PublicKey, message: &[u8]) -> Option<Box<[u8]>> {
    let mut sign_len = 0usize;
    let result = unsafe {
        ffi::pq_sign(&mut sign_len,
                     ptr::null_mut(),
                     private_key.get_bytes().len(),
                     &private_key.get_bytes()[0],
                     public_key.get_bytes().len(),
                     &public_key.get_bytes()[0],
                     message.len(),
                     &message[0])
    };
    if result != 0 {
        return None;
    }

    let mut sign = vec![0u8; sign_len];
    let result = unsafe {
        ffi::pq_sign(&mut sign_len,
                     &mut sign[0],
                     private_key.get_bytes().len(),
                     &private_key.get_bytes()[0],
                     public_key.get_bytes().len(),
                     &public_key.get_bytes()[0],
                     message.len(),
                     &message[0])
    };

    if result != 0 {
        None
    } else {
        Some(sign.into_boxed_slice())
    }
}

/// Verifies a signed message
///
/// This function verifies that a signed message has been signed with the given public key's
/// private key. It will return a boolean indicating if it has been verified or not. Example:
///
/// ```
/// # use ntrumls::params::{ParamSet, XXX_20151024_743};
///
/// # let params = XXX_20151024_743;
/// # let (private_key, public_key) = ntrumls::generate_keys(&params).unwrap();
/// #
/// let mut message = b"Hello from NTRUMLS!";
/// let signature = ntrumls::sign(&private_key, &public_key, message).unwrap();
///
/// let signature = ntrumls::sign(&private_key, &public_key, message).unwrap();
/// assert!(ntrumls::verify(&signature, &public_key, message));
pub fn verify(signature: &[u8], public_key: &PublicKey, message: &[u8]) -> bool {
    let result = unsafe {
        ffi::pq_verify(signature.len(),
                       &signature[0],
                       public_key.get_bytes().len(),
                       &public_key.get_bytes()[0],
                       message.len(),
                       &message[0])
    };

    result == 0
}

/// NTRUMLS private key
#[derive(PartialEq, Eq, Debug, Clone)]
pub struct PrivateKey {
    ffi_key: Box<[u8]>,
}

impl PrivateKey {
    /// Import the actual bytes of the key to the struct
    pub fn import(bytes: &[u8]) -> PrivateKey {
        PrivateKey { ffi_key: bytes.to_vec().into_boxed_slice() }
    }

    /// Get the byte slice of the key
    pub fn get_bytes(&self) -> &[u8] {
        &self.ffi_key
    }
}

/// NTRUMLS public key
#[derive(PartialEq, Eq, Debug, Clone)]
pub struct PublicKey {
    ffi_key: Box<[u8]>,
}

impl PublicKey {
    /// Import the actual bytes of the key to the struct
    pub fn import(bytes: &[u8]) -> PublicKey {
        PublicKey { ffi_key: bytes.to_vec().into_boxed_slice() }
    }

    /// Get the byte slice of the key
    pub fn get_bytes(&self) -> &[u8] {
        &self.ffi_key
    }
}
