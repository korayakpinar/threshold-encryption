use core::panic;
use std::{io::Cursor, time};

use ark_serialize::Read;
use clap::Parser;

use ark_bls12_381::Bls12_381;
use ark_ec::pairing::Pairing;
use ark_std::Zero;
use rand::rngs::OsRng;
use silent_threshold::{
    decryption::agg_dec, encryption::encrypt, kzg::UniversalParams, setup::{get_pk_exp, AggregateKey, PublicKey, SecretKey}, utils::{LagrangePoly, LagrangePolyHelper}
};

type E = Bls12_381;
type G2 = <E as Pairing>::G2;
use tokio;

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

    /// Threshold Count
    #[arg(short)]
    t: usize,
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

    if args.n <= args.t {
        panic!("n can't be equal to or less than t")
    }

    let mut rng = OsRng;
    let n = args.n;
    let k = args.k + 1;
    let t = args.t;

    let mut file = File::open(format!("./lagrangehelpers/{}", n)).unwrap();
    let mut contents = Vec::new();
    let _ = file.read_to_end(&mut contents);
    let cur = Cursor::new(contents);
    let lagrange_helper = LagrangePolyHelper::deserialize_compressed(cur).unwrap();
    drop(file);
 
    let mut file = File::open("transcript-512").unwrap();
    let mut contents = Vec::new();
    let _ = file.read_to_end(&mut contents);
    let cur = Cursor::new(contents);
    let params = UniversalParams::deserialize_compressed(cur).unwrap();
    drop(file);

    let mut sk = Vec::new();
    let mut pk = Vec::new();

    sk.push(SecretKey::<E>::new(&mut rng));
    sk[0].nullify();

    let lagrange_poly = LagrangePoly::new(0, &lagrange_helper);

    pk.push(get_pk_exp(&sk[0], 0, &lagrange_poly));

    for i in 1..k {
        let ti = time::Instant::now();
        let mut file = File::open(format!("keys/{}-pk", i)).unwrap();
        let mut contents = Vec::new();
        let _ = file.read_to_end(&mut contents);
        let cur = Cursor::new(contents);
        let key = PublicKey::<E>::deserialize_uncompressed_unchecked(cur).unwrap();
        pk.push(key);
        
        let mut file = File::open(format!("keys/{}-bls", i)).unwrap();
        let mut contents = Vec::new();
        let _ = file.read_to_end(&mut contents);
        let cur = Cursor::new(contents);
        let key = SecretKey::<E>::deserialize_compressed(cur).unwrap();
        sk.push(key);
        println!("{}: {:#?}", i, ti.elapsed());
    }

    let ti = time::Instant::now();
    let agg_key = AggregateKey::<E>::new(pk.clone(), n, &params);
    println!("{:#?}: elapsed time for aggregation", ti.elapsed());

    // let mut serialized = Vec::new();
    // agg_key.serialize_compressed(&mut serialized).unwrap();

    // println!("{:?}", hex::encode(serialized));

    let ti = time::Instant::now();
    let ct = encrypt::<E>(&agg_key, t, &params);
    println!("{:#?}: elapsed time for encryption", ti.elapsed());

    // compute partial decryptions
    let mut partial_decryptions: Vec<G2> = Vec::new();
    let mut selector: Vec<bool> = Vec::new();

    let mut v = Vec::new();
    for i in 0..t + 1 {
        v.push(i)
    }

    for i in 0..n {
        if v.contains(&i) {
            partial_decryptions.push(sk[i].partial_decryption(ct.gamma_g2));
            selector.push(true)
        } else {
            partial_decryptions.push(G2::zero());
            selector.push(false)
        }
    }

    let ti = time::Instant::now();
    let _dec_key = agg_dec(&partial_decryptions, &ct.sa1, &ct.sa2, t, n, &selector, &agg_key, &params).await;
    println!("{:#?}: elapsed time for decryption", ti.elapsed());

    println!("{}", _dec_key == ct.enc_key);
    
}