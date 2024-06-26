#![allow(non_snake_case, dead_code, unused_variables, unused_imports)]
// TODO: make all the expects into unwraps
use actix_web::{middleware, web, App, HttpRequest, HttpResponse, HttpServer};
use ark_ec::pairing::Pairing;
use ark_ec::AffineRepr;

use ark_bls12_381::{Bls12_381, G1Affine, G2Affine};
use ark_serialize::*;

use sha2::{Sha256, Digest};
use aes::Aes256;
use block_modes::{BlockMode, Cbc};
use block_modes::block_padding::Pkcs7;

#[macro_use]
extern crate lazy_static;

use std;
use std::fs::File;
use std::io::Cursor;
use std::sync::Mutex;

use hex;
use serde_json;
use serde::{Serialize, Deserialize};

use silent_threshold::setup::{AggregateKey, DecryptParams, PublicKey, SecretKey};
use silent_threshold::kzg::UniversalParams;
use silent_threshold::decryption::{agg_dec, part_verify};
use silent_threshold::utils::{KZG, convert_hex_to_g1, convert_hex_to_g2};

type E = Bls12_381;
type G2 = <E as Pairing>::G2;
type G1 = <E as Pairing>::G1;
type Aes256Cbc = Cbc<Aes256, Pkcs7>;

lazy_static! {
    static ref kzg_setup: UniversalParams<E> = {
        let mut file = File::open("transcript.json").unwrap();

        let mut contents: String = String::new();
        file.read_to_string(&mut contents).unwrap();

        println!("size: {}", contents.len());
        let json: KZG = serde_json::from_str::<KZG>(&mut contents).unwrap().into();
        println!("numG1Powers: {}", json.transcripts[3].numG1Powers);

        let powers_of_g = convert_hex_to_g1(&json.transcripts[3].powersOfTau.G1Powers);
        let powers_of_h = convert_hex_to_g2(&json.transcripts[3].powersOfTau.G2Powers);

        UniversalParams { powers_of_g, powers_of_h }
    };

    static ref sk: SecretKey<E> = {
        let mut file = File::open("~/.sk").expect("Can't open the file!");
        let mut contents: String = String::new();
        file.read_to_string(&mut contents).expect("Can't read the file!");
        let mut bytes: Vec<u8> = hex::decode(&contents).expect("Can't decode hex"); // TODO: Fix this
        let mut cursor = Cursor::new(&mut bytes);
        let deserialized: <E as Pairing>::ScalarField = CanonicalDeserialize::deserialize_compressed(&mut cursor).expect("Unable to deserialize the data!");
        SecretKey { sk: deserialized }
    };
}

#[derive(CanonicalSerialize, CanonicalDeserialize)]
struct Parameters {
    decrypt: DecryptParams,
    pks: Vec<PublicKey<E>>,
    parts: Vec<G2>
}

async fn decrypt_part(st: String) -> HttpResponse {
    let bytes = hex::decode(st).expect("Can't decode data from hex!");
    let projective: G2 = G2Affine::deserialize_compressed(bytes.as_slice()).expect("Can't deserialize the data").into();
    
    // gamma_g2 * sk
    let val = projective * sk.sk;
    
    let mut result = Vec::new();
    val.serialize_compressed(&mut result).expect("Can't serialize val");
    HttpResponse::Ok().body(hex::encode(result))
}

async fn decrypt(data: String) -> HttpResponse {
    println!("{}", data);
    let bytes = hex::decode(data).expect("Can't decode data");
    let mut cur = Cursor::new(&bytes);
    let params = Parameters::deserialize_compressed(&mut cur).expect("Can't deserialize Parameters");

    let mut selector: Vec<bool> = Vec::new();
    for _ in 0..params.decrypt.t + 1 {
        selector.push(true);
    }
    for _ in params.decrypt.t + 1..params.decrypt.n {
        selector.push(false);
    }
    
    let aggregated = AggregateKey::<E>::new(params.pks.clone(), &kzg_setup);

    let key = agg_dec(&params.parts, &params.decrypt.sa1, &params.decrypt.sa2, params.decrypt.t, &selector, &aggregated, &kzg_setup);

    let mut hasher = Sha256::new();
    hasher.update(key.to_string().as_bytes());
    let result = hasher.finalize();

    let key = result.as_slice();
    
    let cipher_dec = Aes256Cbc::new_from_slices(&key, &params.decrypt.iv).unwrap();
    let decrypted = cipher_dec.decrypt_vec(&params.decrypt.enc).expect("Failed to decrypt");

    HttpResponse::Ok().body(hex::encode(decrypted))
}

#[derive(CanonicalSerialize, CanonicalDeserialize)]
struct VerifyPart {
    gamma_g2: G2,
    pk: PublicKey<E>,
    g1: G1,
    part_dec: G2
}

async fn verify_decryption_part(data: String) -> HttpResponse {
    println!("{}", data);
    let bytes = hex::decode(data).expect("Can't decode data");
    let mut cur = Cursor::new(&bytes);
    let verify = VerifyPart::deserialize_compressed(&mut cur).expect("Can't deserialize Parameters");
    let p = part_verify(verify.gamma_g2, verify.pk, verify.g1, verify.part_dec);
    if p == true {
        return HttpResponse::Ok().finish();
    }
    HttpResponse::UnavailableForLegalReasons().finish() // LOL
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    env_logger::init_from_env(env_logger::Env::new().default_filter_or("info"));

    log::info!("starting HTTP server at http://localhost:8080");

    HttpServer::new(|| {
        App::new()
            // enable logger
            .wrap(middleware::Logger::default())
            .app_data(web::JsonConfig::default().limit(240000)) // <- limit size of the payload (global configuration)
            .service(web::resource("/partdec").route(web::post().to(decrypt_part)))
            .service(web::resource("/decrypt").route(web::post().to(decrypt)))
            .service(web::resource("/verifydec").route(web::post().to(verify_decryption_part)))
    })
    .bind(("127.0.0.1", 8080))?
    .run()
    .await
}