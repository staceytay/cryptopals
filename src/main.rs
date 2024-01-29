use aes::cipher::{
    generic_array::{typenum::U16, GenericArray},
    BlockEncrypt, KeyInit,
};
use aes::Aes128;
use base64::{engine::general_purpose, Engine as _};
use rand::Rng;
use std::collections::HashMap;

const KEY_LENGTH: usize = 16;
const UNKNOWN_STRING: &'static str = include_str!("../12.txt");

fn main() {
    let oracle = Oracle::new();

    // Step 1: Find block size of the cipher.
    let block_size = find_block_size(&oracle).expect("block size to be found");

    // Step 2 (skipped): Check if function is using ECB.

    // Steps 3 - 6: Attempt to break unknown string as in challenge 12, but
    // taking into account the offset for random prefix and padding.
    let prefix_length = find_random_prefix_length(&oracle, block_size);
    let prefix_blocks = if prefix_length % block_size == 0 {
        prefix_length / block_size
    } else {
        prefix_length / block_size + 1
    };
    let padding = vec![0u8; block_size - (prefix_length % block_size)];

    let total_block_count = oracle.encrypt(&padding).len() / block_size;
    let mut input: Vec<u8> = (0..block_size).into_iter().map(|_| b'A').collect();
    let mut message = Vec::new();
    for block_count in prefix_blocks..total_block_count {
        for i in 0..block_size {
            // Step 4: Create dictionary for every possible last byte.
            let mut map = HashMap::new();
            let mut padded_input = [padding.clone(), input.clone()].concat();
            let len = padded_input.len();
            for ascii_code in 0..=127 {
                padded_input[len - 1] = ascii_code;
                let ciphertext = oracle.encrypt(&padded_input);
                let target_block = block(&ciphertext, prefix_blocks, block_size);
                map.insert(target_block.to_vec(), ascii_code);
            }

            // Step 5: Attempt to match output to one of the dict entries above.
            let crafted_input = &input[0..block_size - i - 1];
            let ciphertext = oracle.encrypt(&[&padding, crafted_input].concat());
            let target_block = block(&ciphertext, block_count, block_size);
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

struct Oracle {
    key: Vec<u8>,
    random_prefix: Vec<u8>,
    unknown: Vec<u8>,
}

impl Oracle {
    fn new() -> Oracle {
        let mut rng = rand::thread_rng();
        Oracle {
            key: generate_random_bytes(KEY_LENGTH),
            random_prefix: generate_random_bytes(rng.gen::<u8>() as usize),
            unknown: general_purpose::STANDARD
                .decode(UNKNOWN_STRING.replace("\n", ""))
                .unwrap(),
        }
    }

    fn encrypt(&self, input: &[u8]) -> Vec<u8> {
        let message = [&self.random_prefix[..], &Vec::from(input), &self.unknown].concat();

        let ciphertext = ecb_encrypt(&message, &self.key);
        ciphertext
    }
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

fn find_block_size(oracle: &Oracle) -> Option<usize> {
    let mut block_size = None;
    let mut last_length = None;
    for i in 0..16 {
        let ciphertext = oracle.encrypt("A".repeat(i).as_bytes());

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

fn find_random_prefix_length(oracle: &Oracle, block_size: usize) -> usize {
    // Find the number of blocks that corresponds to the random prefix.
    let ciphertext_a = oracle.encrypt(b"A");
    let ciphertext_b = oracle.encrypt(b"B");
    let block_pairs = ciphertext_a
        .chunks(block_size)
        .zip(ciphertext_b.chunks(block_size));
    let mut prefix_blocks = 0;
    for (i, (block_a, block_b)) in block_pairs.enumerate() {
        if block_a != block_b {
            prefix_blocks = i;
            break;
        }
    }

    // Find the exact length of the prefix. To do this, we encrypt an input with
    // an increasing length of characters, starting from 1. We compare the last
    // prefix block (position) with the last prefix block from the previous
    // iteration. If we find two blocks of the same bytes, we know that the
    // later padding character went past the boundary into the next block in the
    // ciphertext.  If the prefix blocks are all different across the different
    // [1, block_size] padding size, then the prefix's length is a multiple of
    // block_size.
    let mut padding_count = 0;
    let mut prev_block = None;
    for i in 1..=block_size {
        let ciphertext = oracle.encrypt("A".repeat(i).as_bytes());

        match prev_block {
            Some(pb) if pb == block(&ciphertext, prefix_blocks, block_size) => {
                padding_count = i - 1;
                break;
            }
            _ => prev_block = Some(block(&ciphertext, prefix_blocks, block_size).to_vec()),
        }
    }

    (prefix_blocks + 1) * block_size - padding_count
}

fn block(ciphertext: &[u8], prefix_blocks: usize, block_size: usize) -> &[u8] {
    &ciphertext[prefix_blocks * block_size..(prefix_blocks + 1) * block_size]
}

fn generate_random_bytes(length: usize) -> Vec<u8> {
    let mut rng = rand::thread_rng();
    let mut v = Vec::new();
    for _ in 0..length {
        v.push(rng.gen::<u8>());
    }
    v
}

fn pkcs7pad(block: &[u8], length: usize) -> Vec<u8> {
    let mut padded = Vec::from(block);
    padded.resize(length, (length - block.len()) as u8);
    padded
}
