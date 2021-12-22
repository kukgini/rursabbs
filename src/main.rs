use std::collections::BTreeMap;
use bbs::sm_map;
use bbs::prelude::*;
use bbs::issuer::Issuer;
use bbs::prover::Prover;

fn main() {
    let (pk, sk) = Issuer::new_keys(5).unwrap();
    let signing_nonce = Issuer::generate_signing_nonce();

    // issuer ---(signing_nonce)--> holder
    //
    let link_secret = Prover::new_link_secret();
    let mut messages = BTreeMap::new();
    messages.insert(0, link_secret.clone());
    let (ctx, signature_blinding) = Prover::new_blind_signature_context(&pk, &messages, &signing_nonce).unwrap();

    // holder --(ctx)--> issuer

    let messages = sm_map![
        1 => b"message 1",
        2 => b"message 2",
        3 => b"message 3",
        4 => b"message 4"
    ];

    let blind_signature = Issuer::blind_sign(&ctx, &messages, &sk, &pk, &signing_nonce).unwrap();

    let mut msgs = messages
        .iter()
        .map(|(_, m)| m.clone())
        .collect::<Vec<SignatureMessage>>();
    msgs.insert(0, link_secret.clone());

    let res = Prover::complete_signature(&pk, msgs.as_slice(), &blind_signature, &signature_blinding);

    assert!(res.is_ok());
    println!("ok! {:?}", res.unwrap());
}
