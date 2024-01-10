use aes::cipher::{
    generic_array::{typenum::U16, GenericArray},
    BlockEncrypt, KeyInit,
};
use aes::Aes128;
use base64::{engine::general_purpose, Engine as _};
use rand::Rng;
use std::collections::HashMap;

const UNKNOWN_STRING: &'static str = include_str!("../12.txt");

fn main() {
    let key = generate_random_bytes(16);

    // Step 1: Find block size of the cipher.
    let block_size = find_block_size(&key).expect("block size to be found");

    // Step 2: Check if function is using ECB.
    // TODO

    // Steps 3 - 6: Attempt to break unknown string.
    let block_count = encryption_oracle(b"", &key).len() / block_size;
    let mut input: Vec<u8> = (0..block_size).into_iter().map(|_| b'A').collect();
    let mut message = Vec::new();
    for block in 0..block_count {
        for i in 0..block_size {
            // Step 4: Create dictionary for every possible last byte.
            let mut map = HashMap::new();
            let mut input_block = input.clone();
            for ascii_code in 0..=127 {
                input_block[block_size - 1] = ascii_code;
                let ciphertext = encryption_oracle(&input_block, &key);
                let first_block = &ciphertext[0..block_size];
                map.insert(first_block.to_vec(), ascii_code);
            }

            // Step 5: Attempt to match output to one of the dict entries above.
            let crafted_input = &input[0..block_size - i - 1];
            let ciphertext = encryption_oracle(crafted_input, &key);
            let target_block = &ciphertext[(block * block_size)..((block + 1) * block_size)];
            let ascii_code = *(map.get(target_block).expect("to match an ascii code"));
            message.push(ascii_code);

            // End condition: stop once we get what seems like a padding char.
            if ascii_code < 10 {
                break;
            }

            // Step 6: Prepare to repeat for next char. Append the matching
            // ascii code and rotate the contents of input left to "match" the
            // first i bytes of the target block.
            input[block_size - 1] = ascii_code;
            input.rotate_left(1);
        }
    }

    println!("{:-^64}", "MESSAGE");
    println!("{}", String::from_utf8(message).unwrap());
    println!("{:-^64}", "END");
}

fn encryption_oracle(input: &[u8], key: &[u8]) -> Vec<u8> {
    let unknown = general_purpose::STANDARD
        .decode(UNKNOWN_STRING.replace("\n", ""))
        .unwrap();
    let message = [Vec::from(input), unknown].concat();

    ecb_encrypt(&message, &key)
}

fn ecb_encrypt(bytes: &[u8], key: &[u8]) -> Vec<u8> {
    let key = GenericArray::<u8, U16>::clone_from_slice(key);

    let cipher = Aes128::new(&key);

    let block_size = 16;
    let mut ciphertext = Vec::new();

    let mut iter = bytes.chunks(block_size).peekable();
    while let Some(chunk) = iter.next() {
        // TODO: cleanup the duplication.
        if chunk.len() < block_size {
            let chunk = pkcs7pad(chunk, block_size);
            let mut block = GenericArray::<u8, U16>::clone_from_slice(&chunk);
            cipher.encrypt_block(&mut block);
            ciphertext.extend(block);
        } else {
            let mut block = GenericArray::<u8, U16>::clone_from_slice(&chunk);
            cipher.encrypt_block(&mut block);
            ciphertext.extend(block);
        }
    }
    ciphertext
}

fn cbc_encrypt(bytes: &[u8]) -> Vec<u8> {
    let key = generate_random_bytes(16);
    let key = GenericArray::<u8, U16>::clone_from_slice(&key);
    let cipher = Aes128::new(&key);

    let block_size = 16;
    let iv = generate_random_bytes(block_size);
    let mut ciphertext = Vec::new();
    let mut previous_block = iv;

    let mut iter = bytes.chunks(block_size).peekable();
    while let Some(chunk) = iter.next() {
        if chunk.len() < block_size {
            let chunk = pkcs7pad(chunk, block_size);
            let mut block = GenericArray::<u8, U16>::clone_from_slice(&chunk);
            cipher.encrypt_block(&mut block);
            let ciphertext_block = fixed_xor(&previous_block, &block);
            previous_block = ciphertext_block.clone();
            ciphertext.extend(ciphertext_block);
        } else {
            let mut block = GenericArray::<u8, U16>::clone_from_slice(&chunk);
            cipher.encrypt_block(&mut block);
            let ciphertext_block = fixed_xor(&previous_block, &block);
            previous_block = ciphertext_block.clone();
            ciphertext.extend(ciphertext_block);
        }
    }
    ciphertext
}

fn find_block_size(key: &[u8]) -> Option<usize> {
    let mut block_size = None;
    let mut last_length = None;
    for i in 1..=16 {
        let ciphertext = encryption_oracle("A".repeat(i).as_bytes(), &key);

        match last_length {
            None => last_length = Some(ciphertext.len()),
            Some(length) if ciphertext.len() > length => {
                block_size = Some(ciphertext.len() - length);
                break;
            }
            Some(_) => last_length = Some(ciphertext.len()),
        }
    }
    block_size
}

fn generate_random_bytes(length: usize) -> Vec<u8> {
    let mut rng = rand::thread_rng();
    let mut v = Vec::new();
    for _ in 0..length {
        v.push(rng.gen::<u8>());
    }
    v
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

fn edit_distance(b1: &[u8], b2: &[u8]) -> u32 {
    let mut distance = 0;
    for i in 0..b1.len() {
        for j in 0..u8::BITS {
            if (b1[i] >> j ^ b2[i] >> j) & 1 as u8 == 0b________1 {
                distance += 1;
            }
        }
    }
    distance
}
