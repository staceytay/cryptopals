use aes::cipher::{
    generic_array::{typenum::U16, GenericArray},
    BlockDecrypt, BlockEncrypt, KeyInit,
};
use aes::Aes128;
use base64::{engine::general_purpose, Engine as _};

const IV: [u8; 16] = [0u8; 16];
const FILE: &'static str = include_str!("../10.txt");
const KEY: &'static [u8; 16] = b"YELLOW SUBMARINE";

fn main() {
    let ciphertext = general_purpose::STANDARD
        .decode(FILE.replace("\n", ""))
        .unwrap();
    let message = cbc_decrypt(&IV, KEY, &ciphertext);

    println!("{:-^64}", "MESSAGE");
    println!("{}", String::from_utf8(message).unwrap());
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
