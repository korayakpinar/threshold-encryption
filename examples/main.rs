use actix_web::{App, middleware, get, post, web, HttpServer, HttpResponse};
use ark_ec::pairing::{Pairing, PairingOutput};
use ark_ec::{AffineRepr, CurveGroup};
use log::{debug, error, log_enabled, info, Level};

use ark_bls12_381::{Bls12_381, G1Affine, G2Affine};
use ark_serialize::*;

use rand::rngs::OsRng;
use serde::{Serialize, Deserialize, Serializer, Deserializer};
use serde::de::{self, Visitor};

#[macro_use]
extern crate lazy_static;

use std::borrow::BorrowMut;
use std::fmt;
use std;
use std::fs::File;
use std::io::Cursor;
use std::sync::Mutex;

use rand::Rng;

use silent_threshold::setup::SecretKey;
use silent_threshold::kzg::UniversalParams;
use silent_threshold::decryption::agg_dec;

type E = Bls12_381;
type G2 = <E as Pairing>::G2;
type G1 = <E as Pairing>::G1;

// Add serializer, deserializer
#[derive(Debug, Serialize, Deserialize)]
struct SetupParams {
    enc: Vec<u8>,
    sa1: [G1; 2],
    sa2: [G2; 6],
    n: usize,
    t: usize
}

lazy_static! {
    static ref kzg_setup: Mutex<UniversalParams<E>> = {
        let powers_of_g: Vec<G1Affine> = Vec::new();
        let powers_of_h: Vec<G2Affine> = Vec::new();
        Mutex::new(UniversalParams { powers_of_g, powers_of_h })
    };

    static ref sk: SecretKey<E> = {
        let mut file = File::open("~/.sk").expect("Can't open the file!");
        let mut contents: Vec<u8> = Vec::new();
        file.read(&mut contents).expect("Can't read the file!");
        let mut cursor = Cursor::new(contents.clone());
        let deserialized: <E as Pairing>::ScalarField = CanonicalDeserialize::deserialize_compressed(&mut cursor).expect("Unable to deserialize the data!");
        SecretKey { sk: deserialized }
    };

    static ref partial_decryptions: Mutex<Vec<G2>> = {
        let g2: G2 = G2Affine::from_random_bytes(&[0]).expect("Can't generate random").into();
        Mutex::new(vec![g2])
    };

    static ref C: Mutex<i32> = Mutex::new(0);
    static ref busy: Mutex<i32> = Mutex::new(0);
    static ref params: Mutex<SetupParams> = {
        let g1: G1 = G1Affine::from_random_bytes(&[0]).expect("Can't generate random").into();
        let g2: G2 = G2Affine::from_random_bytes(&[0]).expect("Can't generate random").into();
        let enc: Vec<u8> = Vec::new();
        Mutex::new(SetupParams {
            enc,
            sa1: [g1; 2],
            sa2: [g2; 6],
            n: 0,
            t: 0
        })
    };
}


// Custom Serializer for G2Affine
fn serialize_g2<S>(value: &G2Affine, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let mut bytes = Vec::new();
    value.serialize_compressed(&mut bytes).map_err(serde::ser::Error::custom)?;
    serializer.serialize_bytes(&bytes)
}


// Custom Deserializer for G2Affine
fn deserialize_g2<'de, D>(deserializer: D) -> Result<G2Affine, D::Error>
where
    D: Deserializer<'de>,
{
    struct G2Visitor;

    impl<'de> Visitor<'de> for G2Visitor {
        type Value = G2Affine;

        fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
            formatter.write_str("a valid serialized G2Affine point")
        }

        fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            G2Affine::deserialize_compressed(v).map_err(de::Error::custom)
        }
    }

    deserializer.deserialize_bytes(G2Visitor)
}

#[derive(Debug, Serialize, Deserialize)]
struct G2Point {
    #[serde(serialize_with = "serialize_g2", deserialize_with = "deserialize_g2")]
    pub g2: G2Affine,
}

//#[post("/part_dec")]
async fn part_dec(point: web::Json<G2Point>) -> HttpResponse {
    let projective: G2 = point.0.g2.into();
    println!("{projective}");
    let ret = projective * sk.sk;
    let return_point = G2Point { g2: ret.into_affine() };
    HttpResponse::Ok().json(return_point)
}

//#[post("/setup")]
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

//#[post("/decrypt")]
async fn decrypt(point: web::Json<G2Point>) -> HttpResponse {
    let mut count = C.lock().expect("Couldn't get C");
    let p = params.lock().expect("Couldn't lock params");
    let parts = partial_decryptions.lock().expect("Can't lock the partial decryptions");
    
    let part: G2 = point.0.g2.into();

    if count.abs() == p.t.into() {
        let mut selector: Vec<bool> = Vec::new();
        for _ in 0..p.t + 1 {
            selector.push(true);
        }
        for _ in p.t + 1..p.n {
            selector.push(false);
        }
        agg_dec(&parts, &p.sa1, &p.sa2, p.t, &selector, );
    } else if !parts.contains(&part) {
        *count += 1;
        (*parts).push(part);
    }

    HttpResponse::Ok().json("return_point")
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