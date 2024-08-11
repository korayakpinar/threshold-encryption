use core::panic;
use std::{fs, io::Cursor, path::Path, time};

use ark_serialize::Read;
use clap::Parser;

use ark_bls12_381::Bls12_381;
use rand::{rngs::OsRng, RngCore};
use silent_threshold::{
    api::types::LagrangePoly, setup::{get_pk_exp, SecretKey}, utils::LagrangePolyHelper
};

type E = Bls12_381;

use std::fs::File;
use ark_serialize::*;

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

    let mut file = File::open(format!("./lagrangehelpers/{}", args.n)).unwrap();
    let mut contents = Vec::new();
    let _ = file.read_to_end(&mut contents);
    let cur = Cursor::new(contents);
    let lagrange_helper = LagrangePolyHelper::deserialize_compressed(cur).unwrap();
    drop(file);

    if !Path::new("./keys").exists() {
        fs::create_dir("./keys").unwrap();
    }

    for i in 0..args.k {
        let sk_filename = format!("keys/{}-bls", i + 1);
        let ecdsa_filename = format!("keys/{}-ecdsa", i + 1);

        let mut rng = OsRng;

        // Generate the secret key and serialize
        let sk = SecretKey::<E>::new(&mut rng);
        // Write the secret key to file
        let mut sk_file = File::create(sk_filename).expect("Can't open the file!");
        let mut sk_wr = Vec::new();
        sk.serialize_compressed(&mut sk_wr).unwrap();
        sk_file.write_all(&sk_wr).expect("Can't write to the file!");

        // Generate ECDSA key bytes and serialize
        let mut secret_key_bytes = [0u8; 32];
        rng.fill_bytes(&mut secret_key_bytes);
        let mut ecdsa_wr = Vec::new();
        secret_key_bytes.serialize_compressed(&mut ecdsa_wr).unwrap();

        // Write the ECDSA key to file
        let mut ecdsa_file = File::create(ecdsa_filename).expect("Can't open the file!");
        ecdsa_file.write_all(&ecdsa_wr).expect("Can't write to the file!");
        
        let t = time::Instant::now();

        let lagrange_poly = LagrangePoly::new(i + 1, &lagrange_helper);

        let pk = get_pk_exp(&sk, i + 1, &lagrange_poly);
        println!("{}-pk: {:#?}", pk.id, t.elapsed());
        let mut pk_wr = Vec::new();
        
        let pk_filename = format!("keys/{}-pk", pk.id);
        let mut pk_file = File::create(pk_filename).expect("Can't write to the file!");
        pk.serialize_compressed(&mut pk_wr).unwrap();
        pk_file.write_all(&pk_wr).expect("Can't write to the file!");
    }
    
}