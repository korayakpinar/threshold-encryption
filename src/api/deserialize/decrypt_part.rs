use std::io::Cursor;

use ark_bls12_381::G2Projective;
use ark_serialize::CanonicalDeserialize;

use crate::{api::types::{PartDec, PartDecRequest, E}, setup::SecretKey};

impl PartDecRequest {
    pub fn deserialize(self) -> Option<PartDec> {
        let cur = Cursor::new(self.gamma_g2);
        let tmp = G2Projective::deserialize_compressed(cur);
        if tmp.is_err() {
            log::error!("can't read gamma_g2");
            return None;
        }
        let gamma_g2 = tmp.unwrap();
        
        let cur = Cursor::new(self.sk);
        let tmp = SecretKey::<E>::deserialize_compressed(cur);
        if tmp.is_err() {
            log::error!("can't read sk");
            return None;
        }
        let sk = tmp.unwrap();

        Option::from(
            PartDec {
                sk,
                gamma_g2
            }
        )
    }
}