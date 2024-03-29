use std::borrow::Cow;

use aes::cipher::{
    generic_array::{typenum::U16, GenericArray},
    BlockDecrypt, BlockEncrypt, KeyInit,
};
use aes::Aes128;
use base64::{engine::general_purpose, Engine as _};
use rand::Rng;

const BLOCK_SIZE: usize = 16;
const KEY_LENGTH: usize = 16;

fn main() {
    let oracle = Oracle::new();
    let (ciphertext, iv) = oracle.encrypt();

    let mut plaintext: Vec<u8> = Vec::new();
    for block_index in 0..(ciphertext.len() / BLOCK_SIZE) {
        // The intermediate block is the block produced right after block
        // decryption but before being XOR-ed with the IV / previous ciphertext
        // block.
        let mut intermediate_block = vec![0; BLOCK_SIZE];
        for i in 1..=BLOCK_SIZE {
            // We want to create a tampered block such that passing it in as the
            // IV block to the decryption function produces a valid padding upon
            // decryption.
            let mut tampered_block = vec![0; BLOCK_SIZE];
            for j in 1..=i {
                tampered_block[BLOCK_SIZE - j] = i as u8;
            }
            tampered_block = fixed_xor(&tampered_block, &intermediate_block);
            for code in u8::MIN..=u8::MAX {
                tampered_block[BLOCK_SIZE - i] = code;
                if oracle.decrypt(
                    &ciphertext[block_index * BLOCK_SIZE..(block_index + 1) * BLOCK_SIZE],
                    &tampered_block,
                ) {
                    // Check an edge case where the decryption produces a valid
                    // padding for padding length 1 instead of 2.
                    if i == 1 {
                        tampered_block[BLOCK_SIZE - i - 1] = 22u8;
                        if !oracle.decrypt(
                            &ciphertext[block_index * BLOCK_SIZE..(block_index + 1) * BLOCK_SIZE],
                            &tampered_block,
                        ) {
                            continue;
                        }
                    }
                    intermediate_block[BLOCK_SIZE - i] = code ^ i as u8;
                    break;
                }
            }
        }
        let previous_ciphertext_block = if block_index == 0 {
            &iv
        } else {
            &ciphertext[(block_index - 1) * BLOCK_SIZE..block_index * BLOCK_SIZE]
        };
        plaintext.extend(fixed_xor(previous_ciphertext_block, &intermediate_block));
    }

    println!("{:-^64}", "DECRYPTED PLAINTEXT");
    println!(
        "{}",
        String::from_utf8(
            general_purpose::STANDARD
                .decode(validate_pkcs7pad(&plaintext).unwrap())
                .unwrap()
        )
        .unwrap()
    );
    println!("{:-^64}", "END");
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

    fn encrypt(&self) -> (Vec<u8>, Vec<u8>) {
        let strings = [
            "MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=",
            "MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=",
            "MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==",
            "MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==",
            "MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl",
            "MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==",
            "MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==",
            "MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=",
            "MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=",
            "MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93",
        ];
        let selected_string = strings[rand::thread_rng().gen_range(0..strings.len())];
        let iv = generate_random_bytes(KEY_LENGTH);
        let ciphertext = cbc_encrypt(&iv, &self.key, selected_string.as_bytes());
        (ciphertext, iv)
    }

    fn decrypt(&self, ciphertext: &[u8], iv: &[u8]) -> bool {
        let message = cbc_decrypt(iv, &self.key, ciphertext);
        validate_pkcs7pad(&message).is_ok()
    }
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

    let mut message = Vec::new();
    let mut previous_block = iv;

    let mut iter = bytes.chunks(BLOCK_SIZE).peekable();
    while let Some(chunk) = iter.next() {
        let mut block = GenericArray::<u8, U16>::clone_from_slice(&chunk);
        cipher.decrypt_block(&mut block);
        let message_block = fixed_xor(&previous_block, &block);
        previous_block = chunk.try_into().expect("unexpected chunk length");
        message.extend(message_block);
    }
    message
}

fn cbc_encrypt(iv: &[u8], key: &[u8], bytes: &[u8]) -> Vec<u8> {
    let key = GenericArray::<u8, U16>::clone_from_slice(key);
    let cipher = Aes128::new(&key);

    let padded_bytes = pkcs7pad(bytes);
    let mut ciphertext = Vec::new();
    let mut previous_block = iv.to_vec();

    for block_index in 0..(padded_bytes.len() / BLOCK_SIZE) {
        let intermediate_block = fixed_xor(
            &previous_block,
            &padded_bytes[block_index * BLOCK_SIZE..(block_index + 1) * BLOCK_SIZE],
        );
        let mut block = GenericArray::<u8, U16>::clone_from_slice(&intermediate_block);
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

fn pkcs7pad(bytes: &[u8]) -> Vec<u8> {
    let padding_length = BLOCK_SIZE - (bytes.len() % BLOCK_SIZE);
    let mut padded_bytes = bytes.to_vec();
    padded_bytes.append(&mut vec![padding_length as u8; padding_length]);
    padded_bytes
}

fn validate_pkcs7pad(plaintext: &[u8]) -> Result<Cow<[u8]>, &'static str> {
    let padding_length = *plaintext.last().unwrap();
    if padding_length > 0 && padding_length <= BLOCK_SIZE as u8 {
        for i in 1..=padding_length {
            if plaintext[plaintext.len() - i as usize] != padding_length {
                return Err("invalid padding character");
            }
        }
        return Ok(Cow::Borrowed(
            &plaintext[..plaintext.len() - padding_length as usize],
        ));
    }
    Err("invalid padding character")
}
