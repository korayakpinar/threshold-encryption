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
    decryption::{agg_dec, is_valid, part_verify},
    encryption::encrypt,
    kzg::{UniversalParams, KZG10},
    setup::{get_pk_exp, AggregateKey, PublicKey, SecretKey}, utils::{lagrange_poly, IsValidHelper, LagrangePolyHelper},
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
use tokio::{self, io::AsyncReadExt};

use tokio::fs::File;
use tokio::io::AsyncWriteExt;
use ark_serialize::*;

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// Comittee size
    #[arg(short)]
    n: usize,
}

fn is_equal(pk1: &PublicKey<E>, pk2: &PublicKey<E>) -> bool {
    println!("pk1.bls_pk == pk2.bls_pk: {}", pk1.bls_pk == pk2.bls_pk);
    println!("pk1.id == pk2.id: {}", pk1.id == pk2.id);
    println!("pk1.sk_li == pk2.sk_li: {}", pk1.sk_li == pk2.sk_li);
    println!("pk1.sk_li_by_tau == pk2.sk_li_by_tau: {}", pk1.sk_li_by_tau == pk2.sk_li_by_tau);
    for i in 0..pk1.sk_li_by_z.len() {
        println!("pk1.sk_li_by_z[{i}] == pk2.sk_li_by_z[{i}]: {}", pk1.sk_li_by_z[i] == pk2.sk_li_by_z[i]);
    }
    println!("pk1.sk_li_minus0 == pk2.sk_li_minus0: {}", pk1.sk_li_minus0 == pk2.sk_li_minus0);    

    pk1.bls_pk == pk2.bls_pk && pk1.id == pk2.id && pk1.sk_li == pk2.sk_li && pk1.sk_li_by_tau == pk2.sk_li_by_tau && pk1.sk_li_by_z == pk2.sk_li_by_z && pk1.sk_li_minus0 == pk2.sk_li_minus0
}

#[tokio::main]
async fn main() {
    let args = Args::parse();

    if args.n != 0 && (args.n & (args.n - 1)) != 0 {
        panic!("n should be a power of two");
    }

    let lagrange_polys: Vec<DensePolynomial<<Bls12<ark_bls12_381::Config> as Pairing>::ScalarField>> = (0..args.n)
        .map(|j| lagrange_poly(args.n, j))
        .collect();

    let mut file = File::open("transcript-512").await.expect("Can't open the file!");
    let mut contents = Vec::new();
    let _ = file.read_to_end(&mut contents).await;
    println!("{}", contents.len());
    let cur = Cursor::new(contents);
    let kzg_setup = UniversalParams::<E>::deserialize_compressed(cur).unwrap();
    drop(file);

    let mut rng = OsRng;
    let sk = SecretKey::<E>::new(&mut rng);
    let t = time::Instant::now();
    let lagrange_helper = LagrangePolyHelper::new(&sk, args.n, &kzg_setup).await;
    println!("Elapsed: {:#?}", t.elapsed());

    let t = time::Instant::now();
    let pk = sk.get_pk(0, &kzg_setup, args.n, &lagrange_polys).await;
    println!("elapsed for normal pk: {:#?}", t.elapsed());
    
    let t = time::Instant::now();
    //let pk_exp = get_pk_exp(&sk, 0, args.n, &lagrange_helper);
    println!("elapsed for experimental pk: {:#?}", t.elapsed());

/*     let t = time::Instant::now();
    let is_valid_helper = IsValidHelper::new(args.n).await;
    println!("Elapsed: {:#?}", t.elapsed());

    println!("{}", is_valid(&pk, args.n, &kzg_setup, &is_valid_helper).await);
    println!("{}", is_valid(&pk_exp, args.n, &kzg_setup, &is_valid_helper).await); */
    //println!("{}", is_equal(&pk, &pk_exp));

    if !Path::new("./lagrangehelpers").exists() {
        fs::create_dir("./lagrangehelpers").unwrap();
    }

    let mut file = File::create(format!("./lagrangehelpers/{}", args.n)).await.expect("Can't open the file");
    let mut wr = Vec::new();
    lagrange_helper.serialize_compressed(&mut wr).unwrap();
    file.write_all(&wr).await.expect("Can't write to the file!");


    if !Path::new("./isvalidhelpers").exists() {
        fs::create_dir("./isvalidhelpers").unwrap();
    }

/*     let mut file = File::create(format!("./isvalidhelpers/{}", args.n)).await.expect("Can't open the file");
    let mut wr = Vec::new();
    is_valid_helper.serialize_compressed(&mut wr).unwrap();
    file.write_all(&wr).await.expect("Can't write to the file!"); */
}