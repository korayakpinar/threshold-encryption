use actix_protobuf::{ProtoBuf, ProtoBufResponseBuilder};
use actix_web::{HttpRequest, HttpResponse};

use ark_serialize::*;
use ark_std::log2;

use crate::api::types::*;
use crate::setup::get_pk_exp;


pub async fn get_pk_route(config: HttpRequest, data: ProtoBuf<PKRequest>) -> HttpResponse {
    let datum = config.app_data::<Data>().unwrap();
    let sk = &datum.sk;
    // let params = &datum.kzg_setup;

    let pk_res = data.0.deserialize();
    if pk_res.is_none() {
        log::error!("can't deserialize pk request");
        return HttpResponse::InternalServerError().finish();
    }
    let pk = pk_res.unwrap();

    let l = log2(pk.n) as usize - 1;
    let lagrange_helper = &datum.lagrange_helpers[l];

    let pk = get_pk_exp(sk, pk.id + 1, pk.n, &lagrange_helper);
    
    let mut result = Vec::new();
    let res = pk.serialize_compressed(&mut result);
    if res.is_err() {
        log::error!("can't serialize public key");
        return HttpResponse::InternalServerError().finish();
    }

    let resp = HttpResponse::Ok().protobuf(Response { result });
    if resp.is_err() {
        log::error!("can't cast the result to ResultProto");
        return HttpResponse::InternalServerError().finish();
    }
    resp.unwrap()
}