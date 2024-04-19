use aes::cipher::{
    generic_array::{typenum::U16, GenericArray},
    BlockEncrypt, KeyInit,
};
use aes::Aes128;
use base64::{engine::general_purpose, Engine as _};
use rand::Rng;

const BLOCK_SIZE: usize = 16;
const KEY_LENGTH: usize = 16;
const TEXT: &'static str = include_str!("../19.txt");

fn main() {
    let oracle = Oracle::new(0);

    // Decode strings from base64.
    let mut ciphertexts = Vec::new();
    for line in TEXT.split("\n") {
        let decoded = general_purpose::STANDARD.decode(line).unwrap();
        let ciphertext = oracle.ctr(&decoded);
        ciphertexts.push(ciphertext);
    }

    // Recover plaintext from edit function.
    for (i, ciphertext) in ciphertexts.iter().enumerate() {
        let plaintext = oracle.edit(ciphertext, 0, ciphertext);
        println!("{:0>2}: {}", i + 1, String::from_utf8_lossy(&plaintext));
    }
}

struct Oracle {
    key: Vec<u8>,
    nonce: usize,
}

impl Oracle {
    fn new(nonce: usize) -> Oracle {
        Oracle {
            key: generate_random_bytes(KEY_LENGTH),
            nonce,
        }
    }

    fn ctr(&self, bytes: &[u8]) -> Vec<u8> {
        let key = GenericArray::<u8, U16>::clone_from_slice(&self.key);
        let cipher = Aes128::new(&key);

        let mut count = 0u64;
        let mut input_block = [self.nonce.to_le_bytes(), count.to_le_bytes()].concat();
        let mut message = Vec::new();

        let mut iter = bytes.chunks(BLOCK_SIZE);
        while let Some(chunk) = iter.next() {
            let mut block = GenericArray::<u8, U16>::clone_from_slice(&input_block);
            cipher.encrypt_block(&mut block);

            message.extend(fixed_xor(&block, &chunk));

            count += 1;
            input_block = [self.nonce.to_le_bytes(), count.to_le_bytes()].concat();
        }
        message
    }

    fn edit(&self, ciphertext: &[u8], offset: usize, newtext: &[u8]) -> Vec<u8> {
        let mut plaintext = self.ctr(ciphertext);
        for (i, b) in newtext.iter().enumerate() {
            plaintext[offset + i] = *b;
        }
        self.ctr(&plaintext)
    }
}

fn fixed_xor(b1: &[u8], b2: &[u8]) -> Vec<u8> {
    b1.into_iter()
        .zip(b2.into_iter())
        .map(|(u1, u2)| u1 ^ u2)
        .collect()
}

fn generate_random_bytes(length: usize) -> Vec<u8> {
    let mut rng = rand::thread_rng();
    let mut v = Vec::new();
    for _ in 0..length {
        v.push(rng.gen::<u8>());
    }
    v
}
