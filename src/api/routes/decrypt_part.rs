use actix_protobuf::{ProtoBuf, ProtoBufResponseBuilder};
use actix_web::{HttpRequest, HttpResponse};
use ark_serialize::CanonicalSerialize;

use crate::api::types::*;

pub async fn decrypt_part_route(_: HttpRequest, data: ProtoBuf<PartDecRequest>) -> HttpResponse {
    unsafe { libc::malloc_trim(0); }

    let decrypt_part_res = data.0.deserialize();
    if decrypt_part_res.is_none() {
        unsafe { libc::malloc_trim(0); }
        log::error!("can't deserialize gamma_g2");
        return HttpResponse::BadRequest().finish();
    }
    let decrypt_part = decrypt_part_res.unwrap();

    let sk = decrypt_part.sk;
    let gamma_g2 = decrypt_part.gamma_g2;

    let val = gamma_g2 * sk.sk;
    
    let mut result = Vec::new();
    let res = val.serialize_uncompressed(&mut result);
    if res.is_err() {
        unsafe { libc::malloc_trim(0); }
        log::error!("can't serialize gamma_g2 * sk");
        return HttpResponse::BadRequest().finish();
    }

    drop(sk);

    let resp = HttpResponse::Ok().protobuf(Response { result });
    if resp.is_err() {
        unsafe { libc::malloc_trim(0); }
        log::error!("can't cast the result to ResultProto");
        return HttpResponse::InternalServerError().finish();
    }
    unsafe { libc::malloc_trim(0); }
    resp.unwrap()
}