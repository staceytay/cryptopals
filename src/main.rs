use aes::cipher::{
    generic_array::{typenum::U16, GenericArray},
    BlockEncrypt, KeyInit,
};
use aes::Aes128;

const IV: [u8; 16] = [0u8; 16];
const FILE: &'static str = include_str!("../7.txt");
const KEY: &'static [u8; 16] = b"YELLOW SUBMARINE";

fn main() {
    let ciphertext = cbc_encrypt(KEY, FILE.as_bytes());

    println!("{:-^64}", "CIPHERTEXT");
    println!("{}", show(&ciphertext));
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

// From https://stackoverflow.com/questions/41449708/how-to-print-a-u8-slice-as-text-if-i-dont-care-about-the-particular-encoding.
fn show(bs: &[u8]) -> String {
    let mut visible = String::new();
    for &b in bs {
        let part: Vec<u8> = std::ascii::escape_default(b).collect();
        visible.push_str(std::str::from_utf8(&part).unwrap());
    }
    visible
}
