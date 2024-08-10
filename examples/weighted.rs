use ark_ec::{bls12::Bls12, pairing::Pairing};
use ark_poly::univariate::DensePolynomial;
use ark_std::Zero;
use rand::rngs::OsRng;
use silent_threshold::{
    api::types::{E, G2}, decryption::agg_dec, encryption::encrypt, kzg::{UniversalParams, KZG10}, setup::{AggregateKey, PublicKey, SecretKey}, utils::lagrange_poly
};

type UniPoly381 = DensePolynomial<<E as Pairing>::ScalarField>;

#[tokio::main]
async fn main() {
    let n = 16; // actually n-1 total parties. one party is a dummy party that is always true
    let _k: usize = 6;
    let t: usize = 10;
    debug_assert!(t < n);

    let mut rng = OsRng;
    let params: UniversalParams<E> = KZG10::<E, UniPoly381>::setup(n, &mut rng).unwrap();

    let mut sk: Vec<SecretKey<E>> = Vec::new();
    let mut pk: Vec<PublicKey<E>> = Vec::new();

    let lagrange_polys: Vec<DensePolynomial<<Bls12<ark_bls12_381::Config> as Pairing>::ScalarField>> = (0..n)
        .map(|j| lagrange_poly(n, j))
        .collect();

    // create the dummy party's keys
    sk.push(SecretKey::<E>::new(&mut rng));
    sk[0].nullify();
    pk.push(sk[0].get_pk(0, &params, n, &lagrange_polys).await);

    for _ in 1..9 {
        sk.push(SecretKey::<E>::new(&mut rng));
    }

    for i in 1..9 {
        pk.push(sk[1].get_pk(i, &params, n, &lagrange_polys).await);
    }

    for i in 9..16 {
        pk.push(sk[i - 7].get_pk(i, &params, n, &lagrange_polys).await);
    }

    let agg_key = AggregateKey::<E>::new(pk.clone(), n, &params);
    let ct = encrypt::<E>(&agg_key, t, &params);

    // compute partial decryptions
    let mut partial_decryptions: Vec<G2> = Vec::new();
    let mut selector: Vec<bool> = Vec::new();

    let v: Vec<usize> = vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 12, 14];

    for i in 0..n {
        if v.contains(&i) {
            let mut x = 0;
            if i != 0 && i <= 8 {
                x = 1;
            } else if i > 8 {
                x = i - 7;
            }
            partial_decryptions.push(sk[x].partial_decryption(ct.gamma_g2));
            selector.push(true);
        } else {
            partial_decryptions.push(G2::zero());
            selector.push(false)
        }
    }
    println!("parts: {:#?}\nselector: {:#?}", partial_decryptions, selector);

    let _dec_key = agg_dec(&partial_decryptions, &ct.sa1, &ct.sa2, t, n, &selector, &agg_key, &params).await;

    println!("{}", _dec_key == ct.enc_key);
}