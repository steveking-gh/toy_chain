use blake3;
use bincode;
use chrono::prelude::*;

#[derive(Debug, Clone)]
pub struct BlockHeader {
    /// The nonce is an arbitrary value that cause the hash of the
    /// entire block to meet our difficulty requirement, i.e. number
    /// of leading zeros. The nonce should come at the start (or very
    /// near) of the block to prevent bulk pre-hashing of block
    /// content and making nonce calculations too easy.
    pub nonce : u64,

    /// Timestamp when block header was created.
    pub ts : chrono::DateTime<Utc>,

    /// Hash of the previous block in the chain.
    pub prev_hash : blake3::Hash,
}

impl BlockHeader {
    pub fn new(prev_hash: blake3::Hash) -> Self {
        BlockHeader{ nonce: 0, ts: Utc::now(), prev_hash }
    }

    /// Update the running hash with this header content.
    pub fn hash_update(&self, hasher: &mut blake3::Hasher) {
        // Very annoying that we cannot just derive Serialize for the
        // entire header. The problem is that blake3 does not support
        // serde. Neither does SHA2 or any hash using the digest
        // interface.  SHA1 seems to be only one supporting serde.
        // Would rather do this:
        // hasher.update(&bincode::serialize(&self).unwrap());
        hasher.update(&bincode::serialize(&self.nonce).unwrap());
        hasher.update(&bincode::serialize(&self.ts).unwrap());
        hasher.update(self.prev_hash.as_bytes());
    }

    /// Incrment the nonce in anticipation of another hash attempt.
    pub fn increment_nonce(&mut self) {
        self.nonce += 1;
    }
}

#[derive(Debug, Clone)]
/// The block over which the block chain creates a hash value.
pub struct Block {
    pub header: BlockHeader,
    pub data: String,
}

impl Block {
    pub fn new(msg : &str, prev_hash: blake3::Hash) -> Self {
        Block{ header: BlockHeader::new(prev_hash), data: msg.to_owned() }
    }

    /// Calculate the hash for this block.  Does NOT check if the hash
    /// meets the required difficulty.
    pub fn get_hash(&self, hasher: &mut blake3::Hasher) -> blake3::Hash {
        hasher.reset();
        self.header.hash_update(hasher);
        hasher.update(&bincode::serialize(&self.data).unwrap());
        hasher.finalize()
    }

    /// Increment the nonce in anticipation of another hash attempt.
    pub fn increment_nonce(&mut self) {
        self.header.increment_nonce();
    }
}

pub struct ToyChain {
    pub chain: std::vec::Vec<Block>,

    /// The number of leading zero bits required in the hash represented
    /// as a bit mask.
    /// Ignored for the genesis block.
    pub difficulty_mask: [u8; 4],

    /// The qualified hash value of the last block in the chain.
    pub last_block_hash: blake3::Hash,
}

impl ToyChain {
    pub fn new() -> Self {
        // Start with 8 leading zero bits in the hash as our difficulty.
        // We brute force the nonce until the hash meets this requirement.
        let mut tc = ToyChain { chain: Vec::new(),
                difficulty_mask: [0xFF, 0xFF, 0x00, 0],
                last_block_hash: blake3::hash(b"The genesis hash.")};
        tc.add_first_block();
        tc
    }

    pub fn add_first_block(&mut self) {
        let msg= "The genesis message.";
        let blk = Block::new(msg, self.last_block_hash);
        self.last_block_hash = blake3::hash(msg.as_bytes());
        self.chain.push(blk);
    }

    /// Iterate on the nonce until we have get a hash for this block
    /// that meets the difficulty requirements.
    pub fn get_qualified_hash(&self, blk: &mut Block) -> blake3::Hash {
        let mut hasher = blake3::Hasher::new();
        let mut hash = blk.get_hash(&mut hasher);
        loop {
            // Calculate the block hash, then determine if the hash value
            // has the required number of leading 0 bits.
            let hash_bytes = hash.as_bytes();
            let mut hash_good = true;
            for (byte_num, mask) in self.difficulty_mask.iter().enumerate() {
                if (hash_bytes[31 - byte_num] & mask) != 0 {
                    hash_good = false;
                    break;
                }
            }

            if hash_good {
                break;
            }

            blk.header.increment_nonce();
            hash = blk.get_hash(&mut hasher);
        }
        hash
    }

    pub fn add_msg(&mut self, msg: &str) {
        // The chain is guaranteed to have at least the genesis block
        let mut blk = Block::new(msg, self.last_block_hash);
        self.last_block_hash = self.get_qualified_hash(&mut blk);
        self.chain.push(blk);
    }
}

fn main() {

    let mut chain = ToyChain::new();

    let messages = vec![
        "Beware the naked man who offers you his shirt.",
        "The quick brown fox jumped over the lazy dog.",
        "I got in early on ToyCoin!",
    ];

    for msg in messages {
        println!("Adding message = {}\n", msg);
        chain.add_msg(msg);
    }

    for blk in chain.chain {
        println!("Chain entry block = {:?}", blk);
    }
}
