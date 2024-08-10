use crate::api::types::{PKRequest, PK};

impl PKRequest {
    pub fn deserialize(self) -> Option<PK> {
        return Option::from(
            PK {
                id: self.id as usize,
                n: self.n as usize
            }
        )
    }
}