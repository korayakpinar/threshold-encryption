use std::io::Cursor;

use ark_serialize::CanonicalDeserialize;

use crate::{api::types::{IsValid, IsValidRequest, E}, setup::PublicKey};

impl IsValidRequest {
    pub fn deserialize(self) -> Option<IsValid> {
        let mut cur = Cursor::new(self.pk);
        let pk_res = PublicKey::<E>::deserialize_compressed(&mut cur);
        if pk_res.is_err() {
            return None;
        }
        let pk = pk_res.unwrap();

        return Option::from(
            IsValid {
                pk,
                n: self.n as usize
            }
        )
    }
}