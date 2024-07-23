use actix_web::{middleware, web, App, HttpServer};
use ark_serialize::CanonicalDeserialize;
use ark_serialize::Read;
use clap::{arg, command, Parser};
use silent_threshold::kzg::UniversalParams;
use silent_threshold::setup::SecretKey;
use silent_threshold::utils::convert_hex_to_g1;
use silent_threshold::utils::convert_hex_to_g2;
use std::fs::File;
use std::io::Cursor;

use silent_threshold::utils::KZG;
use silent_threshold::api::routes::*;
use silent_threshold::api::types::*;

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// Path of the transcript.json
    #[arg(short, long)]
    transcript: String,

    /// Path of the BLS private key
    #[arg(short, long)]
    bls_key: String,

    /// Port to start the api
    #[arg(short, long, default_value_t = 8080)]
    api_port: u16,
}


#[actix_web::main]
async fn main() -> std::io::Result<()> {
    env_logger::init_from_env(env_logger::Env::new().default_filter_or("info"));
    
    let args = Args::parse();

    let mut file = File::open(args.transcript).expect("can't open transcript.json");

    let mut contents: String = String::new();
    file.read_to_string(&mut contents).expect("can't read transcript.json to a string");

    log::info!("size: {}", contents.len());
    let json: KZG = serde_json::from_str::<KZG>(&mut contents).expect("can't deserialize data from transcript.json").into();

    let powers_of_g = convert_hex_to_g1(&json.transcripts[3].powersOfTau.G1Powers);
    log::info!("numG1Powers: {}", json.transcripts[3].numG1Powers);

    let powers_of_h = convert_hex_to_g2(&json.transcripts[3].powersOfTau.G2Powers);
    log::info!("numG1Powers: {}", json.transcripts[3].numG2Powers);

    let kzg_setup: UniversalParams<E> = UniversalParams { powers_of_g, powers_of_h };

    let mut file = File::open(args.bls_key).expect("Can't open the file!");
    let mut contents = Vec::new();
    file.read_to_end(&mut contents).expect("Can't read the file!");
    let mut cursor = Cursor::new(contents);
    let sk: SecretKey<E> = CanonicalDeserialize::deserialize_compressed(&mut cursor).expect("Unable to deserialize the data!");

    let data = web::Data::new(Data { kzg_setup, sk });

    log::info!("starting HTTP server at http://localhost:{}", args.api_port);
    HttpServer::new(move || {
        App::new()
            .wrap(middleware::Logger::default())
            .app_data(web::JsonConfig::default().limit(240000)) // <- limit size of the payload (global configuration)
            .app_data(Data::clone(&data))
            .service(web::resource("/encrypt").route(web::post().to(encrypt_route)))
            .service(web::resource("/partdec").route(web::post().to(decrypt_part_route)))
            .service(web::resource("/decrypt").route(web::post().to(decrypt_route)))
            .service(web::resource("/verifydec").route(web::post().to(verify_part_route)))
            .service(web::resource("/getpk").route(web::post().to(get_pk_route)))
    })
    .bind(("127.0.0.1", args.api_port))?
    .run()
    .await
}
