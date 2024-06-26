use actix_web::web::Bytes;
use actix_web::{middleware, web, App, HttpRequest, HttpResponse, HttpServer};
use ark_ec::pairing::Pairing;
use ark_ec::{AffineRepr, CurveGroup};

use ark_bls12_381::{Bls12_381, G1Affine, G2Affine};
use ark_serialize::*;

use sha2::{Sha256, Digest};
use aes::Aes256;
use block_modes::{BlockMode, Cbc};
use block_modes::block_padding::Pkcs7;

use serde::{Serialize, Deserialize};

#[macro_use]
extern crate lazy_static;

use std;
use std::fs::File;
use std::io::Cursor;
use std::sync::{Mutex, MutexGuard};

use hex::{self, ToHex};

use silent_threshold::setup::{AggregateKey, DecryptParams, PublicKey, SecretKey, SetupParams};
use silent_threshold::kzg::UniversalParams;
use silent_threshold::decryption::agg_dec;

type E = Bls12_381;
type G2 = <E as Pairing>::G2;
type G1 = <E as Pairing>::G1;
type Aes256Cbc = Cbc<Aes256, Pkcs7>;

lazy_static! {
    static ref kzg_setup: Mutex<UniversalParams<E>> = {
        let powers_of_g: Vec<G1Affine> = Vec::new();
        let powers_of_h: Vec<G2Affine> = Vec::new();
        Mutex::new(UniversalParams { powers_of_g, powers_of_h })
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

    // TODO: remove
    static ref partial_decryptions: Mutex<Vec<G2>> = {
        let g2: G2 = G2Affine::from_random_bytes(&[0]).expect("Can't generate random").into();
        Mutex::new(vec![g2])
    };

    // TODO: remove the following
    static ref C: Mutex<usize> = Mutex::new(0);
    static ref busy: Mutex<i32> = Mutex::new(0);
    static ref params: Mutex<DecryptParams> = {
        let g1: G1 = G1Affine::from_random_bytes(&[0]).expect("Can't generate random").into();
        let g2: G2 = G2Affine::from_random_bytes(&[0]).expect("Can't generate random").into();
        let enc: Vec<u8> = Vec::new();
        Mutex::new(SetupParams {
            enc,
            sa1: [g1; 2],
            sa2: [g2; 6],
            n: 0,
            t: 0,
            iv: Vec::new()
        })
    };

    static ref public_keys: Mutex<Vec<PublicKey<E>>> = Mutex::new(Vec::new());
}

async fn part_dec(st: String) -> HttpResponse {
    let bytes = hex::decode(st).expect("Can't decode data from hex!");
    let projective: G2 = G2Affine::deserialize_compressed(bytes.as_slice()).expect("Can't deserialize the data").into();
    
    let val = projective * sk.sk;
    
    let mut writer = Vec::new();
    val.serialize_compressed(&mut writer);
    HttpResponse::Ok().body(hex::encode(writer))
}

// TODO: remove this
async fn setup(config: web::Json<SetupParams>) -> HttpResponse {
    let mut b = busy.lock().expect("Can't lock busy");
    let mut p = params.lock().expect("Can't lock params");
    // Fix this part also
    if *b == 0 {
        *b = 1;
        *p = config.0;
    } else {
        return HttpResponse::BadRequest().finish();
    }
    // get the sa1 sa2 n t and remove the other mutexes from lazy_static
    HttpResponse::Ok().json("OK")
}

async fn decrypt(point: web::Json<G2Point>) -> HttpResponse {
    let mut count = C.lock().expect("Couldn't lock C");
    let mut p = params.lock().expect("Couldn't lock params");
    let mut parts = partial_decryptions.lock().expect("Can't lock the partial decryptions");
    let part: G2 = point.0.g2.into();

    if *count == p.t {
        let mut selector: Vec<bool> = Vec::new();
        for _ in 0..p.t + 1 {
            selector.push(true);
        }
        for _ in p.t + 1..p.n {
            selector.push(false);
        }
        let mut kzg = kzg_setup.lock().expect("Can't lock kzg setup");
        
        let mut pks = public_keys.lock().expect("Can't lock public keys");
        let aggregated = AggregateKey::<E>::new(pks.clone(), &(kzg.clone()));

        let key = agg_dec(&parts, &p.sa1, &p.sa2, p.t, &selector, &aggregated, &kzg);

        let mut hasher = Sha256::new();
        hasher.update(key.to_string().as_bytes());
        let result = hasher.finalize();

        let key = result.as_slice();
        
        let cipher_dec = Aes256Cbc::new_from_slices(&key, &p.iv).unwrap();
        let decrypted = cipher_dec.decrypt_vec(&p.enc).unwrap_or(Vec::from([2, 2]));

        // I think this is dangerous and should be placed somewhere else, need you to review this.
        if decrypted == Vec::from([2, 2]) {
            return HttpResponse::BadRequest().finish();
        }
    } else if !parts.contains(&part) {
        *count += 1;
        (*parts).push(part);
    }

    HttpResponse::Ok().finish()
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
            .service(web::resource("/setup").route(web::post().to(setup)))
            .service(web::resource("/decrypt").route(web::post().to(decrypt)))
            .service(web::resource("/partdec").route(web::post().to(part_dec)))
    })
    .bind(("127.0.0.1", 8080))?
    .run()
    .await
}