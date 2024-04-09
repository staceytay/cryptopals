use aes::cipher::{
    generic_array::{typenum::U16, GenericArray},
    BlockEncrypt, KeyInit,
};
use aes::Aes128;
use base64::{engine::general_purpose, Engine as _};
use rand::Rng;
use std::collections::HashMap;

const BLOCK_SIZE: usize = 16;
const KEY_LENGTH: usize = 16;
const TEXT: &'static str = include_str!("../20.txt");

fn main() {
    let key = generate_random_bytes(KEY_LENGTH);

    // Decode strings from base64.
    let mut ciphertexts = Vec::new();
    for line in TEXT.split("\n") {
        let decoded = general_purpose::STANDARD.decode(line).unwrap();
        let ciphertext = ctr(0, &key, &decoded);
        ciphertexts.push(ciphertext);
    }

    // Attempt to break the ciphertexts for the first `min_length` characters of
    // each ciphertext.
    let min_length = ciphertexts.iter().map(Vec::len).min().unwrap();
    let mut predicted_keystream = vec![None; min_length];
    for i in 0..min_length {
        // Store our best guess at which key is the one. First value is the sum
        // of occurences of the letters of the alphabet (in both lower and
        // uppercase) and the space char. Second value is the corresponding key.
        let mut best_guess = (0.0, 0);
        for char in u8::MIN..=u8::MAX {
            let guess = char ^ ciphertexts[0][i];
            let mut plaintext_column = vec![0u8; ciphertexts.len()];
            for (j, ciphertext) in ciphertexts.iter().enumerate() {
                plaintext_column[j] = ciphertext[i] ^ guess;
            }

            // Count freq of each ASCII char appearing.
            let mut freq = HashMap::new();
            for b in plaintext_column.iter() {
                *freq.entry(b).or_insert(0.0) += 1.0;
            }

            let mut sum_occurences = 0.0;
            // TODO: cleanup this part, maybe .concat all the possbile values for b?
            for b in 32..=122 {
                // If i is either the space char or a letter of the
                // alphabet(-ish).
                if b == b' '
                    || b == b','
                    || b == b'-'
                    || b == b'.'
                    || b >= b'a' && b <= b'z'
                    || b >= b'A' && b <= b'Z'
                {
                    match freq.get(&b) {
                        Some(v) => sum_occurences += v,
                        None => (),
                    }
                }
            }

            if sum_occurences > best_guess.0 {
                best_guess.0 = sum_occurences;
                best_guess.1 = guess;
            }
        }
        predicted_keystream[i] = Some(best_guess.1);
    }

    for (i, ciphertext) in ciphertexts.iter().enumerate() {
        let plaintext = ciphertext
            .iter()
            .take(min_length)
            .enumerate()
            .map(|(i, b)| match predicted_keystream[i] {
                None => b'_',
                Some(p) => *b ^ p,
            })
            .collect();
        println!("{:0>2}: {}", i, String::from_utf8(plaintext).unwrap(),);
    }
}

fn ctr(nonce: u64, key: &[u8], bytes: &[u8]) -> Vec<u8> {
    let key = GenericArray::<u8, U16>::clone_from_slice(key);
    let cipher = Aes128::new(&key);

    let mut count = 0u64;
    let mut input_block = [nonce.to_le_bytes(), count.to_le_bytes()].concat();
    let mut message = Vec::new();

    let mut iter = bytes.chunks(BLOCK_SIZE);
    while let Some(chunk) = iter.next() {
        let mut block = GenericArray::<u8, U16>::clone_from_slice(&input_block);
        cipher.encrypt_block(&mut block);

        message.extend(fixed_xor(&block, &chunk));

        count += 1;
        input_block = [nonce.to_le_bytes(), count.to_le_bytes()].concat();
    }
    message
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
