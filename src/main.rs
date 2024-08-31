use actix_web::{middleware, web, App, HttpServer};
use ark_serialize::CanonicalDeserialize;
use ark_serialize::CanonicalSerialize;
use ark_serialize::Read;
use ark_std::log2;
use clap::{arg, command, Parser};
use rand::rngs::OsRng;
use silent_threshold::kzg::UniversalParams;
use silent_threshold::setup::get_pk_exp;
use silent_threshold::setup::AggregateKey;
use silent_threshold::setup::PublicKey;
use silent_threshold::setup::SecretKey;
use silent_threshold::utils::LagrangePoly;
use std::fs::File;
use std::io::Cursor;

use silent_threshold::api::routes::*;
use silent_threshold::api::types::*;

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// Path of the transcript
    #[arg(short, long, default_value_t = String::from("transcript-512"))]
    transcript: String,

    /// Port to start the api
    #[arg(short, long, default_value_t = 8080)]
    api_port: u16,

    /// Mempool api port
    #[arg(short, long, default_value_t = 65534)]
    mempool_port: u16,

    /// Mempool url
    #[arg(short, long, default_value_t = String::from("127.0.0.1"))]
    mempool_url: String,

    /// Committee Size
    #[arg(short, long, default_value_t = 512)]
    committee_size: usize
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
        file.read_to_end(&mut contents).expect("can't read transcript to a string");

        let cursor = Cursor::new(contents);
        kzg_setup = UniversalParams::<E>::deserialize_compressed(cursor).expect("unable to deserialize kzg_setup");
        log::info!("powers_of_g: {}, powers_of_h: {}", kzg_setup.powers_of_g.len(), kzg_setup.powers_of_h.len());
    }

    let client = reqwest::Client::new();
    let mempool = format!("http://{}:{}/poly", args.mempool_url, args.mempool_port);

    let aggregated: AggregateKey<E>;
    {
        let mut pks = Vec::new();
        for f in 1..args.committee_size {
            let mut file = File::open(format!("./keys/{}-pk", f)).expect(format!("can't open public key {}", f).as_str());
            
            let mut contents = Vec::new();
            file.read_to_end(&mut contents).expect(format!("can't read public key {} to a string", f).as_str());

            let cursor = Cursor::new(contents);
            let pk = PublicKey::<E>::deserialize_uncompressed_unchecked(cursor)
                .expect(format!("unable to serialize {}", f).as_str());

            pks.push(pk);
        }

        let log2_n = log2(pks.len()) as usize - 1;
        let req = Poly { log2_n, idx: 0 };

        let mut wr = Vec::new();
        req.serialize_compressed(&mut wr).expect("unable to serialize data for mempool");

        let client = &client;
        let resp = client.post(&mempool).body(wr).send().await.expect("can't get the response from mempool");

        let bytes = resp.bytes().await.expect("can't cast the result to bytes");
        let cur = Cursor::new(bytes);
        let lagrange_poly = LagrangePoly::deserialize_compressed(cur).expect("can't deserialize lagrange poly");

        let mut rng = OsRng;
        let mut sk = SecretKey::new(&mut rng);
        sk.nullify();

        pks.insert(0, get_pk_exp(&sk, 0, &lagrange_poly));

        aggregated = AggregateKey::new(pks.clone(), pks.len(), &kzg_setup);
    }

    let data = web::Data::new(Data { kzg_setup, aggregated, client, mempool });

    log::info!("starting HTTP server at http://localhost:{}", args.api_port);
    HttpServer::new(move || {
        App::new()
            .wrap(middleware::Logger::default())
            .app_data(web::PayloadConfig::new(1024 * 1024 * 100))
            .app_data(Data::clone(&data))
            .service(web::resource("/encrypt").route(web::post().to(encrypt_route)))
            .service(web::resource("/partdec").route(web::post().to(decrypt_part_route)))
            .service(web::resource("/decrypt").route(web::post().to(decrypt_route)))
            .service(web::resource("/verifydec").route(web::post().to(verify_part_route)))
            .service(web::resource("/getpk").route(web::post().to(get_pk_route)))
            .service(web::resource("/isvalid").route(web::post().to(is_valid_route)))
    })
    .bind(("127.0.0.1", args.api_port))?
    .run()
    .await
}
