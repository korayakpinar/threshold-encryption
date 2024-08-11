use std::io::Cursor;

use actix_protobuf::ProtoBuf;
use actix_web::{HttpRequest, HttpResponse};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::log2;

use crate::{api::types::*, decryption::is_valid, utils::IsValidPoly};

pub async fn is_valid_route(config: HttpRequest, data: ProtoBuf<IsValidRequest>) -> HttpResponse {
    unsafe { libc::malloc_trim(0); }

    let datum = config.app_data::<Data>().unwrap();
    let kzg_params = &datum.kzg_setup;

    let isvalid_res = data.0.deserialize();
    if isvalid_res.is_none() {
        unsafe { libc::malloc_trim(0); }
        log::error!("can't deserialize gamma_g2");
        return HttpResponse::BadRequest().finish();
    }
    let isvalid = isvalid_res.unwrap();


    let log2_n = log2(isvalid.n) as usize - 1;
    let req = Poly { log2_n, idx: isvalid.pk.id + 1 };

    let mut wr = Vec::new();
    let serialize_result = req.serialize_compressed(&mut wr);
    if serialize_result.is_err() {
        unsafe { libc::malloc_trim(0); }
        log::error!("can't serialize data!");
        return HttpResponse::InternalServerError().finish();
    }

    let client = &datum.client;
    let resp = client.post(format!("{}valid", datum.mempool)).body(wr).send().await;
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
    let lagrange_poly = IsValidPoly::deserialize_compressed(cur);
    if lagrange_poly.is_err() {
        unsafe { libc::malloc_trim(0); }
        log::error!("can't deserialize bytes from internal api response!");
        return HttpResponse::InternalServerError().finish();
    }

    let p = is_valid(&isvalid.pk, isvalid.n, &kzg_params, &lagrange_poly.unwrap()).await;
    
    if p == true {
        return HttpResponse::Ok().finish();
    }

    drop(isvalid.pk);
    drop(req);

    return HttpResponse::UnavailableForLegalReasons().finish();
}