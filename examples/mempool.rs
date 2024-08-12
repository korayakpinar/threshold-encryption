use std::{fs::File, io::{Cursor, Read}, net::IpAddr};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use clap::{arg, Parser};
use rocket::{data::{Limits, ToByteUnit}, post, routes, Config, State};
use rocket::http::Status;
use silent_threshold::{api::types::Poly, utils::{IsValidHelper, IsValidPoly, LagrangePoly, LagrangePolyHelper}};
use tokio::io::AsyncReadExt;

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// Port to run the code
    #[arg(short, long, default_value_t = 65534)]
    port: u16,

    /// Test mode (only loads lagrangehelpers/2)
    #[arg(short, long, default_value_t = false)]
    test: bool,

    /// Enables endpoint for is_valid route
    #[arg(short, long, default_value_t = false)]
    is_valid: bool
}

#[derive(Clone)]
struct Polys {
    lagrange_polys: Vec<LagrangePolyHelper>,
    isvalid_polys: Vec<IsValidHelper>
}

#[post("/poly", data = "<bytes>")]
async fn poly_route(state: &State<Polys>, bytes: rocket::data::Data<'_>) -> Result<Vec<u8>, Status> {
    unsafe { libc::malloc_trim(0); }

    let mut buf = Vec::new();
    if let Err(_) = bytes.open(1.kilobytes()).read_to_end(&mut buf).await {
        unsafe { libc::malloc_trim(0); }
        return Err(Status::InternalServerError);
    }

    let cur = Cursor::new(buf);
    let poly = match Poly::deserialize_compressed(cur) {
        Ok(p) => p,
        Err(_) => {
            unsafe { libc::malloc_trim(0); };
            return Err(Status::BadRequest)
        },
    };

    let polynomial = state.lagrange_polys[poly.log2_n].clone();
    let res = LagrangePoly::new(poly.idx, &polynomial);

    let mut result = Vec::new();
    if res.serialize_compressed(&mut result).is_err() {
        unsafe { libc::malloc_trim(0); }
        return Err(Status::InternalServerError);
    }

    unsafe { libc::malloc_trim(0); }
    Ok(result)
}

#[post("/polyvalid", data = "<bytes>")]
async fn polyvalid_route(state: &State<Polys>, bytes: rocket::data::Data<'_>) -> Result<Vec<u8>, Status> {
    unsafe { libc::malloc_trim(0); }

    let mut buf = Vec::new();
    if let Err(_) = bytes.open(1.kilobytes()).read_to_end(&mut buf).await {
        unsafe { libc::malloc_trim(0); }
        return Err(Status::InternalServerError);
    }

    let cur = Cursor::new(buf);
    let poly = match Poly::deserialize_compressed(cur) {
        Ok(p) => p,
        Err(_) => {
            unsafe { libc::malloc_trim(0); };
            return Err(Status::BadRequest)
        },
    };

    let polynomial = state.isvalid_polys[poly.log2_n].clone();
    let res = IsValidPoly::new(poly.idx, &polynomial);

    let mut result = Vec::new();
    if res.serialize_compressed(&mut result).is_err() {
        unsafe { libc::malloc_trim(0); }
        return Err(Status::InternalServerError);
    }

    unsafe { libc::malloc_trim(0); }
    Ok(result)
}

#[rocket::main]
async fn main() -> Result<(), std::io::Error> {
    env_logger::init_from_env(env_logger::Env::new().default_filter_or("info"));

    let args = Args::parse();

    let mut lagrange_polys = Vec::new();
    if !args.test {
        let lagrange_paths = ["./lagrangehelpers/2", "./lagrangehelpers/4", "./lagrangehelpers/8", "./lagrangehelpers/16", "./lagrangehelpers/32", "./lagrangehelpers/64", "./lagrangehelpers/128", "./lagrangehelpers/256", "./lagrangehelpers/512"];
        for path in lagrange_paths {
            let mut file = File::open(path).unwrap();
            let mut contents = Vec::new();
            file.read_to_end(&mut contents).expect("Can't read the file!");
            let cursor = Cursor::new(contents);

            let lagrange = LagrangePolyHelper::deserialize_compressed(cursor).unwrap();
            lagrange_polys.push(lagrange);
            log::info!("{}", path);
            drop(file);
        }
    } else {
        let mut file = File::open("./lagrangehelpers/2").unwrap();
        let mut contents = Vec::new();
        file.read_to_end(&mut contents).expect("Can't read the file!");
        let cursor = Cursor::new(contents);

        let lagrange = LagrangePolyHelper::deserialize_compressed(cursor).unwrap();
        lagrange_polys.push(lagrange);
        drop(file);
    }

    let mut isvalid_polys = Vec::new();
    if args.is_valid {
        if !args.test {
            let isvalid_paths: [&str; 9] = ["./isvalidhelpers/2", "./isvalidhelpers/4", "./isvalidhelpers/8", "./isvalidhelpers/16", "./isvalidhelpers/32", "./isvalidhelpers/64", "./isvalidhelpers/128", "./isvalidhelpers/256", "./isvalidhelpers/512"];
            for path in isvalid_paths {
                let mut file = File::open(path).unwrap();
                let mut contents = Vec::new();
                file.read_to_end(&mut contents).expect("Can't read the file!");
                let cursor = Cursor::new(contents);

                let poly = IsValidHelper::deserialize_compressed(cursor).unwrap();
                isvalid_polys.push(poly);
                log::info!("{}", path);
                drop(file);
            }
        } else {
            let mut file = File::open("./isvalidhelpers/2").unwrap();
            let mut contents = Vec::new();
            file.read_to_end(&mut contents).expect("Can't read the file!");
            let cursor = Cursor::new(contents);
    
            let poly = IsValidHelper::deserialize_compressed(cursor).unwrap();
            isvalid_polys.push(poly);
            drop(file);
        }
    }

    let polys_state = Polys { lagrange_polys, isvalid_polys };

    let config = Config {
        address: IpAddr::from([0, 0, 0, 0]),
        port: args.port,
        limits: Limits::new().limit("data-form", 1.kilobytes()),
        ..Default::default()
    };

    let _ = rocket::build()
        .manage(polys_state)
        .configure(&config)
        .mount("/", routes![poly_route, polyvalid_route])
        .launch()
        .await;

    Ok(())
}
