use libc::{c_int, size_t, c_uchar};
use params::ParamSet;

extern "C" {
    // pqntrusign.h
    pub fn pq_gen_key(P: *const ParamSet,
                      privkey_blob_len: *mut size_t,
                      privkey_blob: *mut c_uchar,
                      pubkey_blob_len: *mut size_t,
                      pubkey_blob: *mut c_uchar)
                      -> c_int;

    pub fn pq_sign(packed_sig_len: *mut size_t,
                   packed_sig: *mut c_uchar,
                   private_key_len: size_t,
                   private_key_blob: *const c_uchar,
                   public_key_len: size_t,
                   public_key_blob: *const c_uchar,
                   msg_len: size_t,
                   msg: *const c_uchar)
                   -> c_int;

    pub fn pq_verify(packed_sig_len: size_t,
                     packed_sig: *const c_uchar,
                     public_key_len: size_t,
                     public_key_blob: *const c_uchar,
                     msg_len: size_t,
                     msg: *const c_uchar)
                     -> c_int;
}
