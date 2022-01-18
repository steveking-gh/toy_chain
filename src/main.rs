use blake3;
use bincode;
use chrono::prelude::*;

// Very annoying that we can just derive Serialize for the entire header.
// The problem is that blake3 does not support serde operations.
#[derive(Debug, Clone)]
pub struct BlockHeader {
    // The nonce has to come at the start (or very near) of the hash
    // otherwise, the difficulty of finding a good nonce is too low.
    pub nonce : u64,
    pub ts : chrono::DateTime<Utc>,
    pub prev_hash : blake3::Hash,
}

impl BlockHeader {
    pub fn new(prev_hash: blake3::Hash) -> Self {
        BlockHeader{ nonce: 0, ts: Utc::now(), prev_hash }
    }

    pub fn hash_update(&self, hasher: &mut blake3::Hasher) {
        // Would rather do this, but see comment for header struct:
        // hasher.update(&bincode::serialize(&self.header).unwrap());
        hasher.update(&bincode::serialize(&self.nonce).unwrap());
        hasher.update(&bincode::serialize(&self.ts).unwrap());
        hasher.update(self.prev_hash.as_bytes());
    }

    pub fn increment_nonce(&mut self) {
        self.nonce += 1;
    }
}

#[derive(Debug, Clone)]
pub struct Block {
    pub header: BlockHeader,
    pub data: String,
}

impl Block {
    pub fn new(msg : &str, prev_hash: blake3::Hash) -> Self {
        Block{ header: BlockHeader::new(prev_hash), data: msg.to_owned() }
    }

    pub fn get_hash(&self, hasher: &mut blake3::Hasher) -> blake3::Hash {
        hasher.reset();
        self.header.hash_update(hasher);
        hasher.update(&bincode::serialize(&self.data).unwrap());
        hasher.finalize()
    }

    pub fn increment_nonce(&mut self) {
        self.header.increment_nonce();
    }
}

#[derive(Debug, Clone)]
pub struct ChainEntry {
    blk: Block,
    hash: blake3::Hash,
}

impl ChainEntry {
    pub fn new(blk: Block, hash: blake3::Hash) -> Self {
        ChainEntry{ blk, hash }
    }
}

pub struct ToyChain {
    pub chain: std::vec::Vec<ChainEntry>,

    /// The number of leading zero bits required in the hash
    /// Ignored for the genesis block.
    pub difficulty_mask: [u8; 4],
}

impl ToyChain {
    pub fn new() -> Self {
        // Start with 8 leading zero bits in the hash as our difficulty.
        // We brute force the nonce until the hash meets this requirement.
        let mut tc = ToyChain { chain: Vec::new(), difficulty_mask: [0xFF, 0xFF, 0x00, 0]};
        tc.add_first_block();
        tc
    }

    pub fn add_first_block(&mut self) {
        let msg= "The genesis message.";
        let blk = Block::new(msg, blake3::hash(b"The genesis hash."));
        self.chain.push( ChainEntry::new(blk,blake3::hash(msg.as_bytes())));
    }

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
        let mut blk = Block::new(msg, self.chain.last().unwrap().hash);
        let hash = self.get_qualified_hash(&mut blk);
        self.chain.push(ChainEntry::new(blk, hash));
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

    for ce in chain.chain {
        println!("Chain entry block = {:?}", ce.blk);
        println!("             hash = {:?}", ce.hash);
    }
}
