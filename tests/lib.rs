extern crate rand;
extern crate ntrumls;

use rand::Rng;
use ntrumls::params::{ParamSet, ParamSetId};

const TESTS: u16 = 100;

#[test]
fn test_set_xxx20140508401() {
    test_set(ParamSetId::Xxx20140508401);
}

#[test]
fn test_set_xxx20140508439() {
    test_set(ParamSetId::Xxx20140508439);
}

#[test]
fn test_set_xxx20140508593() {
    test_set(ParamSetId::Xxx20140508593);
}

#[test]
fn test_set_xxx20140508743() {
    test_set(ParamSetId::Xxx20140508743);
}

#[test]
fn test_set_xxx20151024401() {
    test_set(ParamSetId::Xxx20151024401);
}

#[test]
fn test_set_xxx20151024443() {
    test_set(ParamSetId::Xxx20151024443);
}

#[test]
fn test_set_xxx20151024563() {
    test_set(ParamSetId::Xxx20151024563);
}

// #[test]
// fn test_set_xxx20151024509() {
//     test_set(ParamSetId::Xxx20151024509);
// }

#[test]
fn test_set_xxx20151024743() {
    test_set(ParamSetId::Xxx20151024743);
}

#[test]
fn test_set_xxx20151024907() {
    test_set(ParamSetId::Xxx20151024907);
}

fn test_set(id: ParamSetId) {
    let params = ParamSet::get_by_id(id);

    let (private_key, public_key) = ntru_mls::generate_keys(&params).unwrap();
    for _ in 0..TESTS {
        let (_, _) = ntru_mls::generate_keys(&params).unwrap();
    }

    let mut message = [0u8; 256];
    let mut rng = rand::thread_rng();
    for _ in 0..TESTS {
        for i in 0..message.len() {
            message[i] = rng.gen();
        }

        let signature = ntru_mls::sign(&private_key, &public_key, &message).unwrap();

        assert!(ntru_mls::verify(&signature, &public_key, &message));
    }
}
