use std::{fs::File, io::{Cursor, Read, Write}};

use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use clap::Parser;
use rand::rngs::OsRng;
use silent_threshold::{api::types::E, kzg::UniversalParams, setup::{get_pk_exp, AggregateKey, PublicKey, SecretKey}, utils::{LagrangePoly, LagrangePolyHelper}};

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

fn load_lagrange_helper(n: usize) -> LagrangePolyHelper {
    let mut file = File::open(format!("./lagrangehelpers/{}", n)).unwrap();
    let mut contents = Vec::new();
    file.read_to_end(&mut contents).unwrap();
    let cur = Cursor::new(contents);
    println!("Loading lagrange helper...");
    LagrangePolyHelper::deserialize_compressed(cur).unwrap()
}

fn load_universal_params() -> UniversalParams<E> {
    let mut file = File::open("transcript-512").unwrap();
    let mut contents = Vec::new();
    file.read_to_end(&mut contents).unwrap();
    let cur = Cursor::new(contents);
    println!("Loading universal params...");
    UniversalParams::deserialize_compressed(cur).unwrap()
}

fn generate_keys(k: usize, lagrange_helper: &LagrangePolyHelper) -> (Vec<SecretKey<E>>, Vec<PublicKey<E>>) {
    let mut sk = Vec::new();
    let mut pk = Vec::new();
    let mut rng = OsRng;

    sk.push(SecretKey::<E>::new(&mut rng));
    sk[0].nullify();

    let lagrange_poly = LagrangePoly::new(0, lagrange_helper);
    pk.push(get_pk_exp(&sk[0], 0, &lagrange_poly));

    for i in 1..k {
        println!("Generating key {}", i);
        let mut file = File::open(format!("keys/{}-pk", i)).unwrap();
        let mut contents = Vec::new();
        file.read_to_end(&mut contents).unwrap();
        let cur = Cursor::new(contents);
        let key = PublicKey::<E>::deserialize_uncompressed_unchecked(cur).unwrap();
        pk.push(key);
        
        let mut file = File::open(format!("keys/{}-bls", i)).unwrap();
        let mut contents = Vec::new();
        file.read_to_end(&mut contents).unwrap();
        let cur = Cursor::new(contents);
        let key = SecretKey::<E>::deserialize_compressed(cur).unwrap();
        sk.push(key);
    }

    (sk, pk)
}

fn main() {
    let args = Args::parse();

    if args.n != 0 && (args.n & (args.n - 1)) != 0 {
        panic!("n should be a power of two");
    }

    if args.n <= args.k {
        panic!("n can't be equal to or less than k")
    }
    
    let lagrange_helper = load_lagrange_helper(args.n);
    let params = load_universal_params();
    let (_, pk) = generate_keys(args.k + 1, &lagrange_helper);

    let agg_key = AggregateKey::<E>::new(pk, args.n, &params);

    let mut serialized = Vec::new();
    agg_key.serialize_uncompressed(&mut serialized).unwrap();

    let mut file = File::create("./aggregatedkey").unwrap();
    file.write(&serialized).unwrap();

    println!("aggregated key: {}", hex::encode(serialized));
}