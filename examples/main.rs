use actix_web::{App, middleware, get, post, web, HttpServer, HttpResponse};
use ark_ec::pairing::Pairing;
use ark_ec::CurveGroup;
use ark_ff::{BigInt, BigInteger};
use log::{debug, error, log_enabled, info, Level};

use ark_bls12_381::{Bls12_381, G2Affine, G2Projective};
use ark_serialize::*;

use serde::{Serialize, Deserialize, Serializer, Deserializer};
use serde::de::{self, Visitor};

#[macro_use]
extern crate lazy_static;

use std::fmt;
use std;
use std::fs::File;

use silent_threshold::setup::SecretKey;

type E = Bls12_381;
type G2 = <E as Pairing>::G2;

lazy_static! {
    static ref sk: SecretKey<E> = {
        let mut file = File::open("~/.sk").expect("Can't open the file!");
        let mut contents: Vec<u8> = Vec::new();
        file.read(&mut contents);
        let deserialized: <E as Pairing>::ScalarField = CanonicalDeserialize::deserialize_compressed(&mut contents).expect("Unable to deserialize the data!");
        SecretKey { sk: deserialized }
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

//#[post("/partdec")]
async fn part_dec(point: web::Json<G2Point>) -> HttpResponse {
    let projective: G2 = point.0.g2.into();
    println!("{projective}");
    let ret = projective * sk.sk;
    let return_point = G2Point { g2: ret.into_affine() };
    HttpResponse::Ok().json(return_point)
}

async fn decrypt() -> HttpResponse {
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
            .service(web::resource("/partdec").route(web::post().to(part_dec)))
            .service(web::resource("/decrypt").route(web::post().to(decrypt)))
    })
    .bind(("127.0.0.1", 8080))?
    .run()
    .await
}