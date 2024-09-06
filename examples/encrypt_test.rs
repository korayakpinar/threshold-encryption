use core::panic;
use std::{fs::File, io::Cursor, time};

use ark_serialize::Read;
use block_modes::BlockMode;
use clap::Parser;

use ark_bls12_381::Bls12_381;
use rand::{rngs::OsRng, Rng};
use serde::{Serialize, Deserialize};
use reqwest::{header::CONTENT_TYPE, Client};
use serde_json::json;
use sha2::{Sha256, Digest};
use silent_threshold::{
    api::types::Aes256Cbc, encryption::encrypt, kzg::UniversalParams, setup::{get_pk_exp, AggregateKey, PublicKey, SecretKey}, utils::{LagrangePoly, LagrangePolyHelper}
};



use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};

type E = Bls12_381;
use tokio;

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

/*     /// Url
    #[arg(short)]
    url: usize,

    /// ETH count
    #[arg(short)]
    eth: usize,

    /// From address (private key)
    #[arg(short)]
    from: String,

    /// To address (public key)
    #[arg(short)]
    to: String, */
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Params {
    pub hash: String,
    pub encrypted_tx: String,
    pub pk_ids: Vec<u64>,
    pub gamma_g2: Vec<u8>,
    pub threshold: u64,
    pub sa1: Vec<u8>,
    pub sa2: Vec<u8>,
    pub iv: Vec<u8>,
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

    // let client = Client::new();

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

    let agg_key = AggregateKey::<E>::new(pk.clone(), n, &params);
    let ct = encrypt::<E>(&agg_key, t, &params);

    let mut hasher = Sha256::new();
    hasher.update(ct.enc_key.to_string().as_bytes());
    let result = hasher.clone().finalize();

    let key = result.as_slice();

    let iv = &mut [0u8; 16];
    rng.fill(iv);

    let cipher_enc = Aes256Cbc::new_from_slices(key, iv).unwrap();
    
    let enc = cipher_enc.encrypt_vec("asd".as_bytes());
    hasher.update(ct.enc_key.to_string().as_bytes());

    let mut gamma_g2 = Vec::new();
    ct.gamma_g2.serialize_compressed(&mut gamma_g2).unwrap();

    let mut sa1 = Vec::new();
    ct.sa1.serialize_compressed(&mut sa1).unwrap();

    let mut sa2 = Vec::new();
    ct.sa2.serialize_compressed(&mut sa2).unwrap();

    let data = json!({
        "hash": "",
        "encrypted_tx": enc,
        "pk_ids": (0..511).collect::<Vec<u64>>(),
        "gamma_g2": gamma_g2,
        "threshold": args.t,
        "sa1": sa1,
        "sa2": sa2,
        "iv": iv
    });
    println!("{}", data);

/*     let url = format!("http://{}/testencrypt", args.url);

    let res = client.post("")
        .header(CONTENT_TYPE, "application/x-protobuf")
        .send()
        .await
        .unwrap();

    if res.status() != 200 {
        println!("encrypt response isn't 200");
    } */
    
}