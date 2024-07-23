use std::fs::File;

use ark_ec::{bls12::Bls12, pairing::Pairing};
use ark_poly::univariate::DensePolynomial;
use ark_std::Zero;
use rand::rngs::OsRng;
use silent_threshold::{
    api::types::{E, G2}, decryption::agg_dec, encryption::encrypt, kzg::UniversalParams, setup::{AggregateKey, PublicKey, SecretKey}, utils::{convert_hex_to_g1, convert_hex_to_g2, lagrange_poly, KZG}
};

use std::io::prelude::*;
// use ark_serialize::*;

fn main() {
    let mut file = File::open("transcript.json").unwrap();

    let mut contents: String = String::new();
    file.read_to_string(&mut contents).unwrap();

    println!("size: {}", contents.len());
    let json: KZG = serde_json::from_str::<KZG>(&mut contents).unwrap().into();
    println!("numG1Powers: {}", json.transcripts[1].numG1Powers);

    let powers_of_g = convert_hex_to_g1(&json.transcripts[1].powersOfTau.G1Powers);
    let powers_of_h = convert_hex_to_g2(&json.transcripts[1].powersOfTau.G2Powers);

    let params = UniversalParams { powers_of_g, powers_of_h };

    let mut sk: Vec<SecretKey<E>> = Vec::new();
    let mut pk: Vec<PublicKey<E>> = Vec::new();

    ////////
    ////////
    //////// 
    ////////
    //////// 
    ////////
    ////////


    let mut rng = OsRng;
    let n = 8; // actually n-1 total parties. one party is a dummy party that is always true
    let k: usize = 6;
    let t: usize = 4;
    debug_assert!(t < n);

    let lagrange_polys: Vec<DensePolynomial<<Bls12<ark_bls12_381::Config> as Pairing>::ScalarField>> = (0..n)
        .map(|j| lagrange_poly(n, j))
        .collect();

    // create the dummy party's keys
    sk.push(SecretKey::<E>::new(&mut rng));
    sk[0].nullify();
    pk.push(sk[0].get_pk(0, &params, n, &lagrange_polys));

    for i in 1..k {
        sk.push(SecretKey::<E>::new(&mut rng));
        pk.push(sk[i].get_pk(i, &params, n, &lagrange_polys))
    }

    let agg_key = AggregateKey::<E>::new(pk.clone(), n, &params);
    let ct = encrypt::<E>(&agg_key, t, &params);

    // compute partial decryptions
    let mut partial_decryptions: Vec<G2> = Vec::new();
    let mut selector: Vec<bool> = Vec::new();

    let v: Vec<usize> = vec![0, 1, 3, 5, 2];

    for i in 0..n {
        if v.contains(&i) {
            partial_decryptions.push(sk[i].partial_decryption(ct.gamma_g2));
            selector.push(true);
        } else {
            partial_decryptions.push(G2::zero());
            selector.push(false)
        }
    }
    println!("parts: {:#?}\nselector: {:#?}", partial_decryptions, selector);

    // println!("{}", size_of_val(&partial_decryptions[0]));


    let _dec_key = agg_dec(&partial_decryptions, &ct.sa1, &ct.sa2, t, n, &selector, &agg_key, &params);

    println!("{}", _dec_key == ct.enc_key);
}