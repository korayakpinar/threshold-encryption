#![allow(deprecated)]
use actix_web::{middleware, web, App, HttpServer};
use ark_serialize::CanonicalDeserialize;
use ark_serialize::Read;
use silent_threshold::kzg::UniversalParams;
use silent_threshold::setup::SecretKey;
use silent_threshold::utils::convert_hex_to_g1;
use silent_threshold::utils::convert_hex_to_g2;
use std::fs::File;
use std::io::Cursor;

use silent_threshold::utils::KZG;
use silent_threshold::api::routes::*;
use silent_threshold::api::types::*;


#[actix_web::main]
async fn main() -> std::io::Result<()> {
    env_logger::init_from_env(env_logger::Env::new().default_filter_or("info"));
    
    let mut file = File::open("transcript.json").expect("can't open transcript.json");

    let mut contents: String = String::new();
    file.read_to_string(&mut contents).expect("can't read transcript.json to a string");

    log::info!("size: {}", contents.len());
    let json: KZG = serde_json::from_str::<KZG>(&mut contents).expect("can't deserialize data from transcript.json").into();
    log::info!("numG1Powers: {}", json.transcripts[3].numG1Powers);

    let powers_of_g = convert_hex_to_g1(&json.transcripts[3].powersOfTau.G1Powers);
    let powers_of_h = convert_hex_to_g2(&json.transcripts[3].powersOfTau.G2Powers);

    let kzg_setup: UniversalParams<E> = UniversalParams { powers_of_g, powers_of_h };

    let mut file = File::open("tests/sks/24").expect("Can't open the file!");
    let mut contents = Vec::new();
    file.read_to_end(&mut contents).expect("Can't read the file!");
    let mut cursor = Cursor::new(contents);
    let sk: SecretKey<E> = CanonicalDeserialize::deserialize_compressed(&mut cursor).expect("Unable to deserialize the data!");

    let data = web::Data::new(Data {kzg_setup, sk});

    log::info!("starting HTTP server at http://localhost:8080");
    HttpServer::new(move || {
        App::new()
            .wrap(middleware::Logger::default())
            .app_data(web::JsonConfig::default().limit(240000)) // <- limit size of the payload (global configuration)
            .app_data(Data::clone(&data))
            .service(web::resource("/partdec").route(web::post().to(decrypt_part)))
            .service(web::resource("/decrypt").route(web::post().to(decrypt)))
            .service(web::resource("/verifydec").route(web::post().to(verify_decryption_part)))
    })
    .bind(("127.0.0.1", 8080))?
    .run()
    .await
}