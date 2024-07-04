use std::{io::Cursor, mem::size_of_val};

use ark_bls12_381::{Bls12_381, G2Affine};
use ark_ec::{bls12::Bls12, pairing::Pairing};
use ark_poly::univariate::DensePolynomial;
use ark_std::{rand::Rng, Zero};
use generic_array::typenum::PartialDiv;
use rand::rngs::OsRng;
use silent_threshold::{
    decryption::agg_dec, encryption::encrypt, kzg::KZG10, setup::{AggregateKey, PublicKey, SecretKey}, utils::lagrange_poly
};
use sha2::{Sha256, Digest};
use aes::Aes256;
use block_modes::{BlockMode, Cbc};
use block_modes::block_padding::Pkcs7;

type E = Bls12_381;
type G2 = <E as Pairing>::G2;
type UniPoly381 = DensePolynomial<<E as Pairing>::ScalarField>;
type Aes256Cbc = Cbc<Aes256, Pkcs7>;

use ark_serialize::*;

#[derive(Debug, CanonicalSerialize, CanonicalDeserialize)]
struct G2Point {
    pub g2: G2Affine,
}

fn main() {
    let mut rng = OsRng;
    let n = 1 << 5; // actually n-1 total parties. one party is a dummy party that is always true
    let t: usize = 9;
    debug_assert!(t < n);

    let params = KZG10::<E, UniPoly381>::setup(n, &mut rng).unwrap();

    let mut sk: Vec<SecretKey<E>> = Vec::new();
    let mut pk: Vec<PublicKey<E>> = Vec::new();

    let lagrange_polys: Vec<DensePolynomial<<Bls12<ark_bls12_381::Config> as Pairing>::ScalarField>> = (0..n)
        .map(|j| lagrange_poly(n, j))
        .collect();

    // create the dummy party's keys
    sk.push(SecretKey::<E>::new(&mut rng));
    sk[0].nullify();
    pk.push(sk[0].get_pk(0, &params, n, &lagrange_polys));

    for i in 1..n {
        sk.push(SecretKey::<E>::new(&mut rng));
        pk.push(sk[i].get_pk(i, &params, n, &lagrange_polys));

        let mut w = Vec::new();
        pk[i].serialize_compressed(&mut w).unwrap();

        println!("{}", w.len());
    }

    //println!("size of sk[0], {}", std::mem::size_of_val(&sk[2]));
    
    let agg_key = AggregateKey::<E>::new(pk, &params);
    let ct = encrypt::<E>(&agg_key, t, &params);

    println!("Encrypted ciphertext: {:?}", ct.enc_key.to_string());

    let mut w = Vec::new();
    ct.sa2.serialize_compressed(&mut w).unwrap();

    let c = Cursor::new(w);
    let q: [G2; 6] = CanonicalDeserialize::deserialize_compressed(c.clone()).unwrap();

    let z = ct.gamma_g2;
    let c = G2Affine::from(z);
    println!("{} {}", size_of_val(&z), size_of_val(&c));

    println!("{}", ct.sa2 == q);
    // compute partial decryptions
    let mut partial_decryptions: Vec<G2> = Vec::new();
    let mut rr = Vec::new();
    for i in 0..t + 1 {
        let tmp = sk[i].partial_decryption(&ct);
        let mut tmp_1 = Vec::new();
        tmp.serialize_compressed(&mut tmp_1).unwrap();
        rr.extend(tmp_1.iter());
        println!("tmp: {}", sk[i].sk);
        partial_decryptions.push(tmp);
    }
    for _ in t + 1..n {
        partial_decryptions.push(G2::zero());
    }

    let mut writer = Vec::new();
    partial_decryptions.serialize_compressed(&mut writer).unwrap();
    println!("{}", hex::encode(&writer) == hex::encode(&rr));

    // compute the decryption key
    let mut selector: Vec<bool> = Vec::new();
    for _ in 0..t + 1 {
        selector.push(true);
    }
    for _ in t + 1..n {
        selector.push(false);
    }

    let _dec_key = agg_dec(&partial_decryptions, &ct.sa1, &ct.sa2, t, &selector, &agg_key, &params);
    println!("Gamma_G2: {:#?}", ct.gamma_g2);
    let mut s1: Vec<u8> = Vec::new();
    ct.gamma_g2.serialize_compressed(&mut s1).expect("Can't unwrap");
    println!("Gamma_G2: {:#?}", s1);
    //let x = G2Affine::deserialize_compressed(s1);
    let _z = ct.gamma_g2 * sk[1].sk;
    let v = sk[1].sk;
    let mut m = Vec::new();
    v.serialize_uncompressed(&mut m).expect("panic");
    let mut w = Cursor::new(m.clone());
    let fp: <E as Pairing>::ScalarField = CanonicalDeserialize::deserialize_uncompressed(&mut w).expect("panic");
    println!("Bigint {}", v);
    println!("Bigint {}", fp);

    if ct.enc_key == _dec_key {

        // Hash the `enc_key` using SHA-256
        let mut hasher = Sha256::new();
        hasher.update(ct.enc_key.to_string().as_bytes()); // Using `to_string` and converting to bytes
        let result = hasher.finalize();

        // Convert the hash result to a 256-bit AES key
        let key = result.as_slice();

        // Example plaintext to encrypt
        let plaintext = b"Hello, world!";
        println!("Original message: {:?}", plaintext.to_vec());

        // IV (Initialization Vector) should be unique for each encryption
        let iv = &mut [0u8; 16]; // In practice, use a secure random IV
        rng.fill(iv);

        println!("IV: {:?}", iv.to_vec());

        // Create AES-256-CBC cipher for encryption and decryption
        let cipher_enc = Aes256Cbc::new_from_slices(key, iv).unwrap();
        let cipher_dec = Aes256Cbc::new_from_slices(key, iv).unwrap();
        
        // Encrypt the plaintext
        let ciphertext = cipher_enc.encrypt_vec(plaintext);
        println!("Encrypted message: {:?}", ciphertext);

        // Decrypt the ciphertext
        let decrypted_ciphertext = cipher_dec.decrypt_vec(&ciphertext).unwrap();
        println!("Decrypted message: {:?}", decrypted_ciphertext);

        if plaintext == decrypted_ciphertext.as_slice() {
            println!("Encryption & Decryption successful!");
        } else {
            println!("Encryption & Decryption failed!");
            
        }

    } else {
        println!("TSS library screwed up!");
    }
}
