use actix_protobuf::{ProtoBuf, ProtoBufResponseBuilder};
use actix_web::{HttpRequest, HttpResponse};
use ark_serialize::CanonicalSerialize;

use crate::api::types::*;

pub async fn decrypt_part_route(config: HttpRequest, data: ProtoBuf<PartDecRequest>) -> HttpResponse {
    let datum = config.app_data::<Data>().unwrap();
    let sk = datum.sk.clone();

    let decrypt_part_res = data.0.deserialize();
    if decrypt_part_res.is_none() {
        log::error!("can't deserialize gamma_g2");
        return HttpResponse::BadRequest().finish();
    }
    let gamma_g2: G2 = decrypt_part_res.unwrap().gamma_g2;
    
    let val = gamma_g2 * sk.sk;
    
    let mut result = Vec::new();
    let res = val.serialize_compressed(&mut result);
    if res.is_err() {
        log::error!("can't serialize gamma_g2 * sk");
        return HttpResponse::BadRequest().finish();
    }

    let resp = HttpResponse::Ok().protobuf(Response { result });
    if resp.is_err() {
        log::error!("can't cast the result to ResultProto");
        return HttpResponse::InternalServerError().finish();
    }
    resp.unwrap()
}