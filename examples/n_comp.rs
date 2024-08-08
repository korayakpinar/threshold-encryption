use std::time;

use ark_ec::{bls12::Bls12, pairing::Pairing};
use ark_poly::univariate::DensePolynomial;
use ark_std::Zero;
use rand::rngs::OsRng;
use silent_threshold::{
    api::types::{E, G2}, decryption::{agg_dec, is_valid}, encryption::encrypt, kzg::{UniversalParams, KZG10}, setup::{AggregateKey, PublicKey, SecretKey}, utils::{lagrange_poly, IsValidHelper}
};

type UniPoly381 = DensePolynomial<<E as Pairing>::ScalarField>;

#[tokio::main]
async fn main() {
    let n = 64; // actually n-1 total parties. one party is a dummy party that is always true
    let k: usize = 64;
    let t: usize = 32;
    debug_assert!(t < n);

    let mut rng = OsRng;
    let params: UniversalParams<E> = KZG10::<E, UniPoly381>::setup(n, &mut rng).unwrap();

    let mut sk: Vec<SecretKey<E>> = Vec::new();
    let mut pk: Vec<PublicKey<E>> = Vec::new();

    let lagrange_polys: Vec<DensePolynomial<<Bls12<ark_bls12_381::Config> as Pairing>::ScalarField>> = (0..n)
        .map(|j| lagrange_poly(n, j))
        .collect();

    // let helper = IsValidHelper::new(n, &lagrange_polys, &params);

    // create the dummy party's keys
    sk.push(SecretKey::<E>::new(&mut rng));
    sk[0].nullify();
    pk.push(sk[0].get_pk(0, &params, n, &lagrange_polys));

    /*let ti = time::Instant::now();
    if is_valid(pk[0].clone(), n, &params, &helper[0]) {
        println!("{:#?}: {} is valid", ti.elapsed(), 0);
    }*/

    for i in 1..k {
        sk.push(SecretKey::<E>::new(&mut rng));
        let t = time::Instant::now();
        pk.push(sk[i].get_pk(i, &params, n, &lagrange_polys));
        println!("{:#?}: pk[{}]", t.elapsed(), i);

        //let t = time::Instant::now();
        //if is_valid(pk[i].clone(), n, &params, &helper[i]) {
        //    println!("{:#?}: {} is valid", t.elapsed(), i);
        //}
    }

    let agg_key = AggregateKey::<E>::new(pk.clone(), n, &params);
    let ct = encrypt::<E>(&agg_key, t, &params);

    // compute partial decryptions
    let mut partial_decryptions: Vec<G2> = Vec::new();
    let mut selector: Vec<bool> = Vec::new();

    let v: Vec<usize> = vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 63, 62, 61, 60, 59, 58, 57, 56, 55, 20, 25, 44, 43, 42, 41, 40, 51, 34, 36, 37, 38, 39, 27];

    for i in 0..n {
        if v.contains(&i) {
            partial_decryptions.push(sk[i].partial_decryption(ct.gamma_g2));
            selector.push(true);
        } else {
            partial_decryptions.push(G2::zero());
            selector.push(false)
        }
    }
    // println!("parts: {:#?}\nselector: {:#?}", partial_decryptions, selector);

    let ti = time::Instant::now();
    let _dec_key = agg_dec(&partial_decryptions, &ct.sa1, &ct.sa2, t, n, &selector, &agg_key, &params).await;
    println!("{:#?}: elapsed time for decryption", ti.elapsed());

    println!("{}", _dec_key == ct.enc_key);
}