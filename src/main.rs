use actix_web::{middleware, web, App, HttpServer};
// use ark_ec::pairing::Pairing;
// use ark_poly::univariate::DensePolynomial;
use ark_serialize::CanonicalDeserialize;
use ark_serialize::Read;
use clap::{arg, command, Parser};
// use rand::rngs::OsRng;
use silent_threshold::kzg::UniversalParams;
// use silent_threshold::kzg::KZG10;
use silent_threshold::setup::SecretKey;
// use silent_threshold::utils::convert_hex_to_g1;
// use silent_threshold::utils::convert_hex_to_g2;
use std::fs::File;
use std::io::Cursor;

// use silent_threshold::utils::KZG;
use silent_threshold::api::routes::*;
use silent_threshold::api::types::*;

// type UniPoly381 = DensePolynomial<<E as Pairing>::ScalarField>;

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// Path of the transcript
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

    let kzg_setup: UniversalParams<E>;
    {
        let mut file = File::open(args.transcript).expect("can't open transcript.json");

        let mut contents = Vec::new();
        file.read_to_end(&mut contents).expect("can't read transcript.json to a string");

        // println!("size: {}", contents.len());
        // let json: KZG = serde_json::from_str::<KZG>(&mut contents).expect("can't deserialize data from transcript.json").into();

        //let powers_of_g = convert_hex_to_g1(&json.transcripts[0].powersOfTau.G1Powers);
        //println!("numG1Powers: {}", json.transcripts[0].numG1Powers);

        //let powers_of_h = convert_hex_to_g2(&json.transcripts[0].powersOfTau.G2Powers);
        // println!("numG1Powers: {}", json.transcripts[0].numG2Powers);
        let mut cursor = Cursor::new(contents);
        kzg_setup = CanonicalDeserialize::deserialize_compressed(&mut cursor).expect("Unable to deserialize kzg_setup");
        println!("powers_of_g: {}, powers_of_h: {}", kzg_setup.powers_of_g.len(), kzg_setup.powers_of_h.len());
    }
/*
    let mut rng = OsRng;
    let kzg_setup = KZG10::<E, UniPoly381>::setup(65536, &mut rng).unwrap();
    log::info!("powers_of_g: {}, powers_of_h: {}", kzg_setup.powers_of_g.len(), kzg_setup.powers_of_h.len());
*/
    let sk: SecretKey<E>;
    {
        let mut file = File::open(args.bls_key).expect("Can't open the file!");
        let mut contents = Vec::new();
        file.read_to_end(&mut contents).expect("Can't read the file!");
        let mut cursor = Cursor::new(contents);
        sk = CanonicalDeserialize::deserialize_compressed(&mut cursor).expect("Unable to deserialize the data!");
    }

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
