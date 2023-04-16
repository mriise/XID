use serde::{Deserialize, Serialize};

use crate::{ParametersId, Assert, ExpectedSize};


pub trait SimpleHasher {
    const NAME: &'static str;
}

pub trait HashInto {
    fn digest_into(&self, input: &[u8], buf: &mut [u8]) -> (usize, &[u8]);
}

pub trait Hasher<const S: usize> {
    fn digest(&self, input: &[u8]) -> [u8; S];
}

trait DynHasher<const S: usize> {
    fn dyn_hasher(&self) -> &dyn Hasher<S>;
}


#[derive(Serialize, Deserialize)]
pub struct HashNoParams {
    hash_function: String
}

// BLANKETS

impl<T: SimpleHasher> crate::XidParameters for T {
    type Parameters = ();
    fn xid_parameter_id(_: &Self::Parameters) -> Result<crate::ParametersId, ()> {
        let params = HashNoParams{hash_function: T::NAME.to_string()};
        Ok(ParametersId::new(&serde_json::to_vec(&params).unwrap()))
    }
}

// this is technically arbitrary blanket, but we assert T::OUTPUT_SIZE <= S with a little trait magic
impl<T: ExpectedSize + HashInto, const S: usize> Hasher<S> for T {
    #[allow(path_statements)]
    fn digest(&self, input: &[u8]) -> [u8; S] {
        <T as Assert::<S, T>>::LE_EQ;
        let mut buf = [0u8; S];
        self.digest_into(input, &mut buf);
        buf
    }
}



// IMPLEMENTATIONS

// fun borrow hack to get a trait object out of it
struct ShaHasher();

impl SimpleHasher for ShaHasher {
    const NAME: &'static str = "SHA1";
}

impl ExpectedSize for ShaHasher {
    const EXPECTED_SIZE: usize = 32;
}


impl Hasher<32> for ShaHasher {
    fn digest(&self, input: &[u8]) -> [u8; 32] {
        todo!()
    }
}

impl DynHasher<32> for ShaHasher {
    fn dyn_hasher(&self) -> &dyn Hasher<32> {
        self
    }
}


