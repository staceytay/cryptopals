use aes::cipher::{
    generic_array::{typenum::U16, GenericArray},
    BlockDecrypt, BlockEncrypt, KeyInit,
};
use aes::Aes128;
use rand::Rng;

const IV: [u8; 16] = [0u8; 16];
const KEY_LENGTH: usize = 16;

fn main() {
    let oracle = Oracle::new();

    // Assert that encrypt correctly escapes the `;` and `=` characters.
    assert!(!oracle.decrypt(&oracle.encrypt(String::from(";admin=true;"))));

    // We skip calculating the block size and prefix length here as it's been
    // done in challenge 14.
    let block_size = 16;
    let prefix_length = 32;
    let mut ciphertext = oracle.encrypt(String::from("0".repeat(block_size * 2)));
    // Attempt to recreate the block right after the decryption step, but before
    // the XOR step, in CBC decryption.
    let block1 = fixed_xor(
        &ciphertext[prefix_length..(prefix_length + block_size)],
        &b"0".repeat(block_size),
    );
    // XOR block1 with the desired text and use this as a cipher block. Then
    // during CBC decryption, this block will produce the desired plaintext
    // after being XOR-ed with the neighbouring decrypted block.
    let block2 = fixed_xor(b"0000;admin=true;", &block1);
    for i in 0..block_size {
        ciphertext[prefix_length + i] = block2[i];
    }
    assert!(oracle.decrypt(&ciphertext));
}

struct Oracle {
    key: Vec<u8>,
}

impl Oracle {
    fn new() -> Oracle {
        Oracle {
            key: generate_random_bytes(KEY_LENGTH),
        }
    }

    fn encrypt(&self, input: String) -> Vec<u8> {
        let escaped_input = [
            "comment1=cooking%20MCs;userdata=",
            &input.replace(";", "\\;").replace("=", "\\="),
            ";comment2=%20like%20a%20pound%20of%20bacon",
        ]
        .concat()
        .as_bytes()
        .to_vec();

        let ciphertext = cbc_encrypt(&self.key, &escaped_input);
        ciphertext
    }

    fn decrypt(&self, ciphertext: &[u8]) -> bool {
        println!("DECRYPT 1 = {}", String::from_utf8_lossy(ciphertext));
        let message = cbc_decrypt(&IV, &self.key, ciphertext);
        println!("DECRYPT 2 = {}", String::from_utf8_lossy(&message));
        bytes_contain(&message, ";admin=true;".as_bytes())
    }
}

// Modified from
// https://stackoverflow.com/questions/35901547/how-can-i-find-a-subsequence-in-a-u8-slice.
fn bytes_contain(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
        .is_some()
}

fn generate_random_bytes(length: usize) -> Vec<u8> {
    let mut rng = rand::thread_rng();
    let mut v = Vec::new();
    for _ in 0..length {
        v.push(rng.gen::<u8>());
    }
    v
}

fn cbc_decrypt(iv: &[u8], key: &[u8], bytes: &[u8]) -> Vec<u8> {
    let key = GenericArray::<u8, U16>::clone_from_slice(key);
    let cipher = Aes128::new(&key);

    let block_size = 16;
    let mut message = Vec::new();
    let mut previous_block = iv;

    let mut iter = bytes.chunks(block_size).peekable();
    while let Some(chunk) = iter.next() {
        let mut block = GenericArray::<u8, U16>::clone_from_slice(&chunk);
        cipher.decrypt_block(&mut block);
        let message_block = fixed_xor(&previous_block, &block);
        previous_block = chunk.try_into().expect("unexpected chunk length");
        message.extend(message_block);
    }
    message
}

fn cbc_encrypt(key: &[u8], bytes: &[u8]) -> Vec<u8> {
    let key = GenericArray::<u8, U16>::clone_from_slice(key);
    let cipher = Aes128::new(&key);

    let block_size = 16;
    let mut ciphertext = Vec::new();
    let mut previous_block = IV.clone();

    let mut iter = bytes.chunks(block_size).peekable();
    while let Some(chunk) = iter.next() {
        let mut chunk: Vec<u8> = chunk.to_vec();
        if iter.peek().is_none() {
            chunk = pkcs7pad(&chunk, block_size);
        }
        let message_block = fixed_xor(&previous_block, &chunk);
        let mut block = GenericArray::<u8, U16>::clone_from_slice(&message_block);
        cipher.encrypt_block(&mut block);
        previous_block = block
            .as_slice()
            .try_into()
            .expect("unexpected block length");
        ciphertext.extend(block);
    }
    ciphertext
}

fn fixed_xor(b1: &[u8], b2: &[u8]) -> Vec<u8> {
    b1.into_iter()
        .zip(b2.into_iter())
        .map(|(u1, u2)| u1 ^ u2)
        .collect()
}

fn pkcs7pad(block: &[u8], length: usize) -> Vec<u8> {
    let mut padded = Vec::from(block);
    padded.resize(length, (length - block.len()) as u8);
    padded
}
