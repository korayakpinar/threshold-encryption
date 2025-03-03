use actix_protobuf::ProtoBuf;
use actix_web::{HttpRequest, HttpResponse};

use crate::decryption::part_verify;

use crate::api::types::*;

pub async fn verify_part_route(config: HttpRequest, data: ProtoBuf<VerifyPartRequest>) -> HttpResponse {
    let datum = config.app_data::<Data>().unwrap();
    let kzg_setup = datum.kzg_setup.clone();

    let verify_res = data.0.deserialize();
    if verify_res.is_none() {
        log::error!("can't deserialize decrypt params");
        return HttpResponse::InternalServerError().finish();
    }
    let verify = verify_res.unwrap();

    let p = part_verify(verify.gamma_g2, &verify.pk, kzg_setup.powers_of_g[0].into(), verify.part_dec);
    if p == true {
        return HttpResponse::Ok().finish();
    }

    HttpResponse::UnavailableForLegalReasons().finish() // LOL
}