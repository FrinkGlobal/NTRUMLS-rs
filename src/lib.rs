extern crate libc;

pub mod params;
mod ffi;

use std::ptr;
use params::ParamSet;

pub fn generate_keys(params: &ParamSet) -> Option<(Box<[u8]>, Box<[u8]>)> {
    let (mut privkey_blob_len, mut pubkey_blob_len) = (0usize, 0usize);

    let result = unsafe { ffi::pq_gen_key(params, &mut privkey_blob_len, ptr::null_mut(),
                                          &mut pubkey_blob_len, ptr::null_mut()) };
    if result != 0 { return None }

    let mut privkey_blob = vec![0u8; privkey_blob_len];
    let mut pubkey_blob = vec![0u8; pubkey_blob_len];
    let result = unsafe { ffi::pq_gen_key(params, &mut privkey_blob_len,
                                          &mut privkey_blob[..][0], &mut pubkey_blob_len,
                                          &mut pubkey_blob[..][0]) };

    if result != 0 { None } else {
        Some((privkey_blob.into_boxed_slice(), pubkey_blob.into_boxed_slice()))
    }
}

pub fn sign(private_key: &[u8], public_key: &[u8], message: &[u8]) -> Option<Box<[u8]>> {
    let mut sign_len = 0usize;
    let result = unsafe { ffi::pq_sign(&mut sign_len, ptr::null_mut(), private_key.len(),
                                  &private_key[0], public_key.len(), &public_key[0], message.len(),
                                  &message[0]) };
    if result != 0 { return None }

    let mut sign = vec![0u8; sign_len];
    let result = unsafe { ffi::pq_sign(&mut sign_len, &mut sign[0], private_key.len(),
                                       &private_key[0], public_key.len(), &public_key[0],
                                       message.len(), &message[0]) };

    if result != 0 { None } else {
        Some(sign.into_boxed_slice())
    }
}

pub fn verify(signature: &[u8], public_key: &[u8], message: &[u8]) -> bool {
    let result = unsafe { ffi::pq_verify(signature.len(), &signature[0], public_key.len(),
                                         &public_key[0], message.len(), &message[0]) };

    println!("sign_len: {}", signature.len());
    result == 0
}
