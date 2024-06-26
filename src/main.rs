#![allow(non_snake_case, dead_code, unused_variables, unused_imports)]
use std::{fs::File, io::Cursor};

use ark_serialize::Read;
use serde::{Deserialize, Serialize};
use serde_json;
use hex;

use ark_bls12_381::{Bls12_381, G1Affine, G2Affine};
use ark_ec::pairing::Pairing;
use ark_std::{rand::Rng, Zero};
use rand::rngs::OsRng;
use silent_threshold::{
    decryption::{agg_dec, part_verify},
    encryption::encrypt,
    kzg::UniversalParams,
    setup::{AggregateKey, PublicKey, SecretKey},
};
use sha2::{Sha256, Digest};
use aes::Aes256;
use block_modes::{BlockMode, Cbc};
use block_modes::block_padding::Pkcs7;

type E = Bls12_381;
type G1 = <E as Pairing>::G1;
type G2 = <E as Pairing>::G2;
type Aes256Cbc = Cbc<Aes256, Pkcs7>;

use ark_serialize::*;


#[derive(Serialize, Deserialize)]
struct Powers {
    G1Powers: Vec<String>,
    G2Powers: Vec<String>
}

#[derive(Serialize, Deserialize)]
struct Witness {
    runningProducts: Vec<String>,
    potPubkeys: Vec<String>,
    blsSignatures: Vec<String>
}

#[derive(Serialize, Deserialize)]
struct Transcript {
    numG1Powers: u32,
    numG2Powers: u32,
    powersOfTau: Powers,
    witness: Witness
}

#[derive(Serialize, Deserialize)]
struct KZG {
    transcripts: Vec<Transcript>
}

fn convert_hex_to_g1(g1_powers: &Vec<String>) -> Vec<G1Affine> {
    let mut g1_powers_decompressed = Vec::new();

    let mut j = 0;
    let len = g1_powers.len();
    for i in g1_powers {
        let g1_vec: Vec<u8> = hex::decode(i.clone().split_off(2)).unwrap();
        let mut cur = Cursor::new(g1_vec);
        let g1 = G1Affine::deserialize_compressed(&mut cur).unwrap();
        g1_powers_decompressed.push(g1);
        print!("{}/{}\t\r", j, len);
        // println!("{:#?}", g1);
        j += 1;
    }
    print!("\n");

    g1_powers_decompressed
}

fn convert_hex_to_g2(g2_powers: &Vec<String>) -> Vec<G2Affine> {
    let mut g2_powers_decompressed = Vec::new();
    let mut j = 0;
    let len = g2_powers.len();
    for i in g2_powers {
        let g2_powers: Vec<u8> = hex::decode(i.clone().split_off(2)).unwrap();
        let mut cur = Cursor::new(g2_powers);
        let g2 = G2Affine::deserialize_compressed(&mut cur).unwrap();
        g2_powers_decompressed.push(g2);
        print!("{}/{}\t\r", j, len);
        j += 1;
        // println!("{:#?}", g2);
    }
    print!("\n");

    g2_powers_decompressed
}

fn main() {
    let mut file = File::open("transcript.json").unwrap();

    let mut contents: String = String::new();
    file.read_to_string(&mut contents).unwrap();

    println!("size: {}", contents.len());
    let json: KZG = serde_json::from_str::<KZG>(&mut contents).unwrap().into();
    println!("numG1Powers: {}", json.transcripts[3].numG1Powers);

    let powers_of_g = convert_hex_to_g1(&json.transcripts[2].powersOfTau.G1Powers);
    let powers_of_h = convert_hex_to_g2(&json.transcripts[2].powersOfTau.G2Powers);

    let n = 1 << 5;
    let t: usize = 4;
    let params = UniversalParams { powers_of_g, powers_of_h };

    let mut sk: Vec<SecretKey<E>> = Vec::new();
    let mut pk: Vec<PublicKey<E>> = Vec::new();

    let mut rng = OsRng;
    sk.push(SecretKey::<E>::new(&mut rng));
    sk[0].nullify();
    pk.push(sk[0].get_pk(0, &params, n));

    for i in 1..n {
        sk.push(SecretKey::<E>::new(&mut rng));
        pk.push(sk[i].get_pk(i, &params, n))
    }

    //println!("size of sk[0], {}", std::mem::size_of_val(&sk[2]));
    
    let agg_key = AggregateKey::<E>::new(pk.clone(), &params);
    let ct = encrypt::<E>(&agg_key, t, &params);

    println!("Encrypted ciphertext: {:?}", ct.enc_key.to_string());

    // compute partial decryptions
    let mut partial_decryptions: Vec<G2> = Vec::new();
    for i in 0..t + 1 {
        let tmp = sk[i].partial_decryption(&ct);
        let x = part_verify(ct.gamma_g2, (pk.clone()).get(i).unwrap().to_owned(), params.powers_of_g[0].into(), tmp.clone());
        println!("part_verify = {}", x);
        partial_decryptions.push(tmp);
    }
    for _ in t + 1..n {
        partial_decryptions.push(G2::zero());
    }

    // compute the decryption key
    let mut selector: Vec<bool> = Vec::new();
    for _ in 0..t + 1 {
        selector.push(true);
    }
    for _ in t + 1..n {
        selector.push(false);
    }

    let _dec_key = agg_dec(&partial_decryptions, &ct.sa1, &ct.sa2, t, &selector, &agg_key, &params);
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