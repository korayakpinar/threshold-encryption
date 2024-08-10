#![allow(non_snake_case, dead_code, unused_variables, unused_imports)]
use core::panic;
use std::{borrow::Borrow, env, fs, io::Cursor, os, path::Path, sync::{Arc, Once}, time::{self, Duration, Instant}};

use actix_web::body::MessageBody;
use ark_poly::univariate::DensePolynomial;
use ark_serialize::Read;
use clap::Parser;
use serde::{Deserialize, Serialize};
use hex::{self, ToHex};

use ark_bls12_381::{Bls12_381, G1Affine, G2Affine};
use ark_ec::{bls12::Bls12, pairing::Pairing};
use ark_std::{rand::Rng, Zero};
use rand::{rngs::OsRng, RngCore};
use silent_threshold::{
    decryption::{agg_dec, part_verify},
    encryption::encrypt,
    kzg::{UniversalParams, KZG10},
    setup::{AggregateKey, PublicKey, SecretKey}, utils::lagrange_poly,
};
use sha2::{Sha256, Digest};
use aes::Aes256;
use block_modes::{BlockMode, Cbc};
use block_modes::block_padding::Pkcs7;

type E = Bls12_381;
type G1 = <E as Pairing>::G1;
type G2 = <E as Pairing>::G2;
type UniPoly381 = DensePolynomial<<E as Pairing>::ScalarField>;
type Aes256Cbc = Cbc<Aes256, Pkcs7>;
use tokio;

use tokio::fs::File;
use tokio::io::AsyncWriteExt;
use ark_serialize::*;

static mut LAGRANGE_POLYS: Option<&'static [DensePolynomial<<Bls12<ark_bls12_381::Config> as Pairing>::ScalarField>]> = None;
static LAGRANGE_INIT: Once = Once::new();

static mut KZG_SETUP: Option<UniversalParams<Bls12_381>> = None;
static KZG_INIT: Once = Once::new();

fn initialize_lagrange_polys(n: usize) {
    let polys: Vec<DensePolynomial<<Bls12<ark_bls12_381::Config> as Pairing>::ScalarField>> = (0..n)
        .map(|j| lagrange_poly(n, j))
        .collect();
    unsafe {
        LAGRANGE_POLYS = Some(Box::leak(polys.into_boxed_slice()));
    }
}

fn get_lagrange_polys() -> &'static [DensePolynomial<<Bls12<ark_bls12_381::Config> as Pairing>::ScalarField>] {
    unsafe {
        LAGRANGE_POLYS.expect("LAGRANGE_POLYS has not been initialized")
    }
}

fn initialize_kzg_setup(n: usize) {
    let mut rng = OsRng;
    let kzg_setup: UniversalParams<E> = KZG10::<E, UniPoly381>::setup(n, &mut rng).unwrap();
    unsafe {
        KZG_SETUP = Some(kzg_setup);
    }
}

fn get_kzg_setup() -> &'static UniversalParams<Bls12_381> {
    unsafe {
        KZG_SETUP.as_ref().expect("KZG_SETUP has not been initialized")
    }
}

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// Comittee size
    #[arg(short)]
    n: usize,

    /// Key count
    #[arg(short)]
    k: usize,
}

#[tokio::main]
async fn main() {
    let args = Args::parse();

    if args.n != 0 && (args.n & (args.n - 1)) != 0 {
        panic!("n should be a power of two");
    }

    if args.n <= args.k {
        panic!("n can't be equal to or less than k")
    }

    KZG_INIT.call_once(|| {
        initialize_kzg_setup(args.n);
    });

    let kzg_setup = get_kzg_setup();

    let mut file = File::create("transcript").await.expect("Can't open the file!");
    let mut wr = Vec::new();
    kzg_setup.clone().serialize_compressed(&mut wr).unwrap();
    file.write_all(&wr).await.expect("Can't write to the file!");

    println!("powers_of_g: {}, powers_of_h: {}", kzg_setup.powers_of_g.len(), kzg_setup.powers_of_h.len());

    LAGRANGE_INIT.call_once(|| {
        initialize_lagrange_polys(args.n);
    });

    // Get the static reference to the LAGRANGE_POLYS
    let lagrange_polys: &'static [DensePolynomial<<Bls12<ark_bls12_381::Config> as Pairing>::ScalarField>] = get_lagrange_polys();

    if !Path::new("./keys").exists() {
        fs::create_dir("./keys").unwrap();
    }

    let mut tasks = Vec::new();
    for i in 0..args.k {
        let sk_filename = format!("keys/{}-bls", i + 1);
        let pk_filename = format!("keys/{}-pk", i + 1);
        let ecdsa_filename = format!("keys/{}-ecdsa", i + 1);
        let kzg_setup = kzg_setup.clone(); // Clone for the async block
        let lagrange_polys = lagrange_polys.to_vec(); // Clone the vec to pass to the async block

        let task = tokio::spawn(async move {
            let t = time::Instant::now();
            let mut rng = OsRng;

            // Generate the secret key and serialize
            let sk = SecretKey::<E>::new(&mut rng);
            // Write the secret key to file
            let mut sk_file = File::create(sk_filename).await.expect("Can't open the file!");
            let mut sk_wr = Vec::new();
            sk.serialize_compressed(&mut sk_wr).unwrap();
            sk_file.write_all(&sk_wr).await.expect("Can't write to the file!");

            // Generate ECDSA key bytes and serialize
            let mut secret_key_bytes = [0u8; 32];
            rng.fill_bytes(&mut secret_key_bytes);
            let mut ecdsa_wr = Vec::new();
            secret_key_bytes.serialize_compressed(&mut ecdsa_wr).unwrap();

            // Write the ECDSA key to file
            let mut ecdsa_file = File::create(ecdsa_filename).await.expect("Can't open the file!");
            ecdsa_file.write_all(&ecdsa_wr).await.expect("Can't write to the file!");
            println!("{}: {:#?}", i, t.elapsed());
            
            let t = time::Instant::now();
            let pk = sk.get_pk(i + 1, &kzg_setup, args.n, &lagrange_polys);
            let mut pk_file = File::create(pk_filename).await.expect("Can't write to the file!");
            let mut pk_wr = Vec::new();
            pk.await.serialize_compressed(&mut pk_wr).unwrap();
            pk_file.write_all(&pk_wr).await.expect("Can't write to the file!");
            println!("{}-pk: {:#?}", i, t.elapsed());
        });

        tasks.push(task);
    }

    for task in tasks {
        task.await.expect("Task failed");
    }
}