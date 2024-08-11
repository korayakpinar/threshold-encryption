use actix_web::{middleware, web, App, HttpServer};
use ark_serialize::CanonicalDeserialize;
use ark_serialize::Read;
use clap::{arg, command, Parser};
use silent_threshold::kzg::UniversalParams;
use silent_threshold::setup::SecretKey;
use std::fs::File;
use std::io::Cursor;
// use console_subscriber;

use silent_threshold::api::routes::*;
use silent_threshold::api::types::*;

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// Path of the transcript
    #[arg(short, long, default_value_t = String::from("transcript-512"))]
    transcript: String,

    /// Path of the BLS private key
    #[arg(short, long)]
    bls_key: String,

    /// Port to start the api
    #[arg(short, long, default_value_t = 8080)]
    api_port: u16,

    /// Mempool api port
    #[arg(short, long, default_value_t = 65534)]
    mempool_port: u16,
}


#[actix_web::main]
async fn main() -> std::io::Result<()> {
    // console_subscriber::init();
    env_logger::init_from_env(env_logger::Env::new().default_filter_or("info"));
    
    let args = Args::parse();

    let kzg_setup: UniversalParams<E>;
    {
        let mut file = File::open(args.transcript).expect("can't open transcript");

        let mut contents = Vec::new();
        file.read_to_end(&mut contents).expect("can't read transcript.json to a string");

        let cursor = Cursor::new(contents);
        kzg_setup = UniversalParams::<E>::deserialize_compressed(cursor).expect("Unable to deserialize kzg_setup");
        log::info!("powers_of_g: {}, powers_of_h: {}", kzg_setup.powers_of_g.len(), kzg_setup.powers_of_h.len());
        drop(file);
    }

    let sk: SecretKey<E>;
    {
        let mut file = File::open(args.bls_key).expect("Can't open the file!");
        let mut contents = Vec::new();
        file.read_to_end(&mut contents).expect("Can't read the file!");
        let cursor = Cursor::new(contents);
        sk = SecretKey::<E>::deserialize_compressed(cursor).expect("Unable to deserialize the data!");
        drop(file);
    }

    let client = reqwest::Client::new();
    let mempool = format!("http://127.0.0.1:{}/poly", args.mempool_port);
    let data = web::Data::new(Data { kzg_setup, sk, client, mempool });

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
            .service(web::resource("/is_valid").route(web::post().to(is_valid_route)))
    })
    .bind(("127.0.0.1", args.api_port))?
    .run()
    .await
}
