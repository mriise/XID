// NOTE this is highly opinionated

// Short context hash is trucated bytes from the long context hash, such that there can be an easy corrilation between the two (assuming any collisions in the short context is resolveable). 

// This intentionally does not use multihash and multicodec as prefixes to the context hashes. Reasons as follows:
// - this is already a long ID, adding 2-3 more bytes (depending on hash fn and length) is a bit much
// - the goal is to have the context hashes be constant size (and simple), allowing for faster and easier implementations
// Future changes in hash function or parameter encoding should be a seperate entry on the multicodec table. The motivation for using blake3 is for its cryptographic security and that it outputs the same hash despite different output lenghts as opposed to blake2 and sha3. 
// In my opinion, it is slightly less confusing to say 4 or 32 bytes of blake3 instead of blake2b-256 truncated to 8 bytes or sha512 truncated to 32 bytes etc. This is especially important for the block context, as one can simply truncate the block context hash to produce the smaller XID

// As an optimization I imagine that a top level XID would contain the long block context and links underneath can use the short version wihtout worries of collision 

// For extremely minimal implementations, they can completely ignore how the context is created and just use the context hash as a simple ID and compare it against a hard-coded list of what they accept. I expect this will be most common in client and user applications, while servers will care more about context and will probable be able to produce their own custom contexts.

// Although silly, Xid can be encoded directly in a CIDv1.

// If data is inlined into the ID (like identity CIDs), then id context should be all zeros (TODO) and 

use std::{fmt::{LowerHex, Debug}, hash::Hasher};

use libipld_cbor::DagCborCodec;
use libipld_core::{codec::Encode, };
use sha::utils::DigestExt;
use tinyvec::ArrayVec;

// not secure at all, only accept already known or very trusted contexts, not safe for fetching context from network or from untrusted sources. Not sutible for contexts with lots of potential params.
// it is expected that a sparce table is shipped with commonly known context IDs (trucated hashes), and if needed- will query from trusted sources in order to understand how to interpit the data
// NOTE if a collision is found in the short codec table, there should be a salt added to the the less senior context hash until a collision is not reached. How such salt is added should be dependant on the trusted implementation/source.
type ShortContextHash = [u8; 4];
// suitable to be used for data with large and widely varying contexts and for data in potentially untrusted contexts
type LongContextHash = [u8; 32];

#[derive(Debug)]
enum XidError {
    InternalError,
}

// multicodec 0x0a
#[derive(Clone, Copy)]
pub struct XidShort {
    block_context: ShortContextHash,
    /// 4 bytes of blake3 hash 
    id_context: [u8; 4],
    // Data MUST be less than or equal to 64 bytes 
    // some reasons:
    // - this nudges users away from inlining data into the XID (that should be done with the long version if needed)
    // - most cryptographic hash lenghts are no larger than 512 bits anyways
    // - this constraint on size lets implementations always put this on stack
    data: tinyvec::ArrayVec<[u8; 64]>,
}

// multicodec 0x0b
#[derive(Clone, Copy)]
pub struct XidLong {
    // I feel it is a reasonable assumption that the id context should remain 4 bytes, not only for space, but for forcing users to consider carefully about their variants of identification
    // block context however should be a full 32 bytes, since there can be a whole subtree of information about the block that needs to be looked up.
    block_context: LongContextHash,
    /// 4 bytes of blake3 hash 
    id_context: [u8; 4],
    // TODO set limits on data length, at least 2kB, maybe 512. Data can be inlined into the ID, but ideally we want to avoid alloc
    data: tinyvec::ArrayVec<[u8; 512]>,
}


trait Xid: Sized {
    const MULTICODEC: u8;

    fn new(id_context: impl Encode<DagCborCodec>, block_context: impl Encode<DagCborCodec>, data: &[u8]) -> Result<Self, XidError>;

    fn id_data(&self) -> &[u8];

    fn id_context_hash(&self) -> &[u8];

    fn block_context_hash(&self) -> &[u8];

    /// panics if buffer is too small
    fn write_into(&self, buf: &mut [u8]) {
        buf[0] = Self::MULTICODEC;
        let buf = &mut buf[1..];

        let id_context_len = self.id_context_hash().len();
        let block_context_len = self.block_context_hash().len();

        buf[..id_context_len].copy_from_slice(self.id_context_hash());
        let buf = &mut buf[id_context_len..];
        buf[..block_context_len].copy_from_slice(self.block_context_hash());
        let buf = &mut buf[block_context_len..];

        buf[..self.id_data().len()].copy_from_slice(self.id_data())
    }
}

impl From<XidShort> for Vec<u8> {
    fn from(value: XidShort) -> Self {
        let mut v = Vec::new();
        v.extend([&[XidShort::MULTICODEC], value.block_context_hash(), value.id_context_hash(), value.id_data()].concat());
        v
    }
}

// multibase encoding should be used for text display (like CIDs), though it is omitted in the binary form
impl LowerHex for XidShort {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&multibase::encode(multibase::Base::Base16Lower, [&[Self::MULTICODEC], self.block_context_hash(), self.id_context_hash(), self.id_data()].concat()))
    }
} 

impl Debug for XidShort {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("XidShort")
            .field("block_context", &hex::encode(self.block_context_hash()))
            .field("id_context", &hex::encode(self.id_context_hash()))
            .field("id_data", &hex::encode(self.id_data()))
            .finish()
    }
}

impl Xid for XidShort {
    const MULTICODEC: u8 = 0x0a;

    fn new(id_context: impl Encode<DagCborCodec>, block_context: impl Encode<DagCborCodec>, data: &[u8]) -> Result<Self, XidError> {
        let mut id_buf = Vec::new();
        // TODO no panic
        id_context.encode(DagCborCodec, &mut id_buf).map_err(|_| XidError::InternalError)?;

        let mut block_buf = Vec::new();
        block_context.encode(DagCborCodec, &mut block_buf).map_err(|_| XidError::InternalError)?;

        let mut id_ch = ShortContextHash::default();
        let mut b_ch = ShortContextHash::default();
        let mut hasher = blake3::Hasher::default();
        hasher.update(&id_buf).finalize_xof().fill(&mut id_ch);
        hasher.reset();
        hasher.update(&id_buf).finalize_xof().fill(&mut b_ch);

        Ok(Self { id_context: id_ch, block_context: b_ch, data: ArrayVec::try_from(data).map_err(|_| XidError::InternalError)? })
    }

    fn id_context_hash(&self) -> &[u8] {
        &self.id_context
    }

    fn block_context_hash(&self) -> &[u8] {
        &self.block_context
    }

    fn id_data(&self) -> &[u8] {
        self.data.as_slice()
    }
}


#[test]
fn foo() {
    let id_ctx = libipld_macro::ipld!({
        "name": "foo",
        "length": 1,
    });

    let b_ctx = libipld_macro::ipld!({
        "codec": "dag-cbor",
    });


    let a = XidShort::new(id_ctx, b_ctx, &[0xff]).unwrap();
    println!("{:?}\n{:x}\n{}-{}-{}", a, a, hex::encode(a.block_context_hash()), hex::encode(a.id_context_hash()), hex::encode(a.id_data()))
}

#[test]
fn sha() {
    let id_ctx = libipld_macro::ipld!({
        "name": "sha",
        "length": 32,
    });

    let b_ctx = libipld_macro::ipld!({
        "codec": "dag-cbor",
    });
    
    let mut hasher = sha::sha256::Sha256::default();
    hasher.write(&[0xb0, 0xba]);
    let a = XidShort::new(id_ctx, b_ctx, &hasher.to_bytes()).unwrap();
    println!("{:?}\n{:x}", a, a)
}
