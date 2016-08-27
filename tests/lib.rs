#![forbid(missing_docs, warnings)]
#![deny(deprecated, improper_ctypes, non_shorthand_field_patterns, overflowing_literals,
    plugin_as_library, private_no_mangle_fns, private_no_mangle_statics, stable_features,
    unconditional_recursion, unknown_lints, unsafe_code, unused, unused_allocation,
    unused_attributes, unused_comparisons, unused_features, unused_parens, while_true)]
#![warn(trivial_casts, trivial_numeric_casts, unused, unused_extern_crates, unused_import_braces,
    unused_qualifications, unused_results, variant_size_differences)]

extern crate rand;
extern crate ntrumls;

use rand::Rng;
use ntrumls::params::{ParamSet, XXX_20140508_401, XXX_20140508_439, XXX_20140508_593,
                      XXX_20140508_743, XXX_20151024_401, XXX_20151024_443, XXX_20151024_563,
                      XXX_20151024_743, XXX_20151024_907};

const TESTS: u16 = 100;

#[test]
fn test_set_xxx_20140508_401() {
    test_set(XXX_20140508_401);
}

#[test]
fn test_set_xxx_20140508_439() {
    test_set(XXX_20140508_439);
}

#[test]
fn test_set_xxx_20140508_593() {
    test_set(XXX_20140508_593);
}

#[test]
fn test_set_xxx_20140508_743() {
    test_set(XXX_20140508_743);
}

#[test]
fn test_set_xxx_20151024_401() {
    test_set(XXX_20151024_401);
}

#[test]
fn test_set_xxx_20151024_443() {
    test_set(XXX_20151024_443);
}

#[test]
fn test_set_xxx_20151024_563() {
    test_set(XXX_20151024_563);
}

// #[test]
// fn test_set_xxx_20151024_509() {
//     test_set(XXX_20151024_509);
// }

#[test]
fn test_set_xxx_20151024_743() {
    test_set(XXX_20151024_743);
}

#[test]
fn test_set_xxx_20151024_907() {
    test_set(XXX_20151024_907);
}

fn test_set(params: ParamSet) {
    let (private_key, public_key) = ntrumls::generate_keys(&params).unwrap();
    for _ in 0..TESTS {
        let (_, _) = ntrumls::generate_keys(&params).unwrap();
    }

    let mut message = [0u8; 256];
    let mut rng = rand::thread_rng();
    for _ in 0..TESTS {
        for i in 0..message.len() {
            message[i] = rng.gen();
        }

        let signature = ntrumls::sign(&private_key, &public_key, &message).unwrap();
        assert!(ntrumls::verify(&signature, &public_key, &message));
    }
}
