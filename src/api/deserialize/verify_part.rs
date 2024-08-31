use std::io::Cursor;

use ark_bls12_381::G2Projective;
use ark_serialize::CanonicalDeserialize;

use crate::{api::types::{VerifyPart, VerifyPartRequest, E}, setup::PublicKey};

impl VerifyPartRequest {
    pub fn deserialize(self) -> Option<VerifyPart> {
        let mut cur = Cursor::new(self.gamma_g2);
        let mut tmp_g2 = G2Projective::deserialize_compressed(cur);
        if tmp_g2.is_err() {
            log::error!("can't read gamma_g2");
            return None;
        }
        let gamma_g2 = tmp_g2.unwrap();
    
        cur = Cursor::new(self.pk);
        let tmp_pk = PublicKey::<E>::deserialize_compressed(cur);
        if tmp_pk.is_err() {
            log::error!("can't read pk");
            return None;
        }
        let pk = tmp_pk.unwrap();
    
        cur = Cursor::new(self.part_dec);
        tmp_g2 = G2Projective::deserialize_compressed(cur);
        if tmp_g2.is_err() {
            log::error!("can't read part_dec");
            return None;
        }
        let part_dec = tmp_g2.unwrap();
    
        Option::from(
            VerifyPart {
                gamma_g2,
                pk,
                part_dec
            }
        )
    }
}
