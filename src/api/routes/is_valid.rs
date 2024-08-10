use actix_protobuf::ProtoBuf;
use actix_web::{HttpRequest, HttpResponse};

use crate::decryption::is_valid;

use crate::api::types::*;

pub async fn is_valid_route(config: HttpRequest, data: ProtoBuf<IsValidRequest>) -> HttpResponse {
    let datum = config.app_data::<Data>().unwrap();
    let kzg_setup = datum.kzg_setup.clone();

    let valid_res = data.0.deserialize();
    if valid_res.is_none() {
        log::error!("can't deserialize decrypt params");
        return HttpResponse::InternalServerError().finish();
    }
    let valid = valid_res.unwrap();

    // let p = is_valid(&valid.pk, valid.n, &kzg_setup).await;
    let p = true;
    if p == true {
        return HttpResponse::Ok().finish();
    }

    HttpResponse::UnavailableForLegalReasons().finish() // LOL
}