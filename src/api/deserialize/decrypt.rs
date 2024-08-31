use std::{collections::HashMap, io::Cursor};

use ark_bls12_381::G2Projective;
use ark_serialize::CanonicalDeserialize;

use crate::api::types::{Decrypt, DecryptRequest, G1, G2};
// use crate::{api::types::E, setup::PublicKey};

impl DecryptRequest {
    pub fn deserialize(self) -> Option<Decrypt> { 
        let cur = Cursor::new(self.sa1);
        let tmp_sa1 = CanonicalDeserialize::deserialize_compressed(cur);
        if tmp_sa1.is_err() {
            log::error!("can't deserialize sa1");
            return None;
        }
        let sa1: [G1; 2] = tmp_sa1.unwrap();

        let q = Cursor::new(self.sa2);
        let tmp_sa2 = CanonicalDeserialize::deserialize_compressed(q);
        if tmp_sa2.is_err() {
            log::error!("can't deserialize sa2");
            return None;
        }
        let sa2: [G2; 6] = tmp_sa2.unwrap();

        let mut parts = HashMap::new();
        for part in self.parts {
            let cur = Cursor::new(part.1);
            let tmp_part = G2Projective::deserialize_uncompressed_unchecked(cur);
            if tmp_part.is_err() {
                log::error!("can't deserialize part {}", part.0);
                return None;
            }
            parts.insert(part.0 as usize, tmp_part.unwrap());
        }

        let cur = Cursor::new(self.gamma_g2);
        let tmp_gamma_g2 = G2Projective::deserialize_compressed(cur);
        if tmp_gamma_g2.is_err() {
            log::error!("can't deserialize gamma_g2");
            return None;
        }
        let gamma_g2 = tmp_gamma_g2.unwrap();

        Option::from(
            Decrypt {
                enc: self.enc,
                /* pks, */
                parts,
                gamma_g2,
                sa1,
                sa2,
                iv: self.iv,
                n: self.n as usize,
                t: self.t as usize
            }
        )
    }
}