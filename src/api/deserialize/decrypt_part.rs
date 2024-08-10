use std::io::Cursor;

use ark_serialize::CanonicalDeserialize;

use crate::api::types::{PartDec, PartDecRequest};

impl PartDecRequest {
    pub fn deserialize(self) -> Option<PartDec> {
        let cur = Cursor::new(self.gamma_g2);
        let tmp = CanonicalDeserialize::deserialize_compressed(cur);
        if tmp.is_err() {
            log::error!("can't read gamma_g2");
            return None;
        }
        let gamma_g2 = tmp.unwrap();
        Option::from(
            PartDec {
                gamma_g2
            }
        )
    }
}