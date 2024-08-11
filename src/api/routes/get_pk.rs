use std::time;
use std::io::Cursor;

use actix_protobuf::{ProtoBuf, ProtoBufResponseBuilder};
use actix_web::{HttpRequest, HttpResponse};

use ark_serialize::*;
use ark_std::log2;

use crate::api::types::*;
use crate::setup::get_pk_exp;
use crate::utils::LagrangePoly;


pub async fn get_pk_route(config: HttpRequest, data: ProtoBuf<PKRequest>) -> HttpResponse {
    unsafe { libc::malloc_trim(0); }

    let ti = time::Instant::now();
    let datum = config.app_data::<Data>().unwrap();
    let sk = &datum.sk;

    let pk_res = data.0.deserialize();
    if pk_res.is_none() {
        unsafe { libc::malloc_trim(0); }
        log::error!("can't deserialize pk request");
        return HttpResponse::InternalServerError().finish();
    }
    let pk = pk_res.unwrap();

    let log2_n = log2(pk.n) as usize - 1;
    let req = Poly { log2_n, idx: pk.id + 1 };

    let mut wr = Vec::new();
    let serialize_result = req.serialize_compressed(&mut wr);
    if serialize_result.is_err() {
        unsafe { libc::malloc_trim(0); }
        log::error!("can't serialize data!");
        return HttpResponse::InternalServerError().finish();
    }

    let client = &datum.client;
    let resp = client.post(&datum.mempool).body(wr).send().await;
    if resp.is_err() {
        unsafe { libc::malloc_trim(0); }
        log::error!("can't reach internal api!, {:?}", resp.err());
        return HttpResponse::InternalServerError().finish();
    }
    let bytes = resp.unwrap().bytes().await;
    if bytes.is_err() {
        unsafe { libc::malloc_trim(0); }
        log::error!("can't read bytes from internal api response!");
        return HttpResponse::InternalServerError().finish();
    }
    let cur = Cursor::new(bytes.unwrap());
    let lagrange_poly = LagrangePoly::deserialize_compressed(cur);
    if lagrange_poly.is_err() {
        unsafe { libc::malloc_trim(0); }
        log::error!("can't deserialize bytes from internal api response!");
        return HttpResponse::InternalServerError().finish();
    }
    
    let pk = get_pk_exp(sk, pk.id + 1, &lagrange_poly.unwrap());

    let mut result = Vec::new();
    let res = pk.serialize_compressed(&mut result);
    if res.is_err() {
        unsafe { libc::malloc_trim(0); }
        log::error!("can't serialize public key");
        return HttpResponse::InternalServerError().finish();
    }

    drop(pk);
    drop(req);

    let resp = HttpResponse::Ok().protobuf(Response { result });
    if resp.is_err() {
        unsafe { libc::malloc_trim(0); }
        log::error!("can't cast the result to ResultProto");
        return HttpResponse::InternalServerError().finish();
    }
    log::info!("elapsed on getpk: {:#?}", ti.elapsed());
    unsafe { libc::malloc_trim(0); }
    resp.unwrap()
}