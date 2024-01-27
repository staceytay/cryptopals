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
    println!("block_size: {block_size}");

    // Step 2: TODO: Check if function is using ECB.

    // Find length of random prefix.
    let ciphertext_a = encryption_oracle(b"A", &key);
    let ciphertext_b = encryption_oracle(b"B", &key);
    let block_pairs = ciphertext_a
        .chunks(block_size)
        .zip(ciphertext_b.chunks(block_size));
    let mut block_position = 0;
    for (i, (block_a, block_b)) in block_pairs.enumerate() {
        if block_a != block_b {
            block_position = i;
            break;
        }
    }
    println!("block_position = {block_position}");

    let mut padding_count = 0;
    let mut last_block = None;
    for i in 1..=16 {
        let ciphertext = encryption_oracle("A".repeat(i).as_bytes(), &key);

        match last_block {
            None => {
                last_block = Some(
                    (&ciphertext[block_position * block_size..(block_position + 1) * block_size])
                        .to_vec(),
                )
            }
            Some(block) => {
                if block
                    == &ciphertext[block_position * block_size..(block_position + 1) * block_size]
                {
                    padding_count = i - 1;
                    break;
                } else {
                    last_block = Some(
                        (&ciphertext
                            [block_position * block_size..(block_position + 1) * block_size])
                            .to_vec(),
                    );
                }
            }
        }
    }
    println!("padding_count = {padding_count}");
    let padding = b"A".repeat(padding_count);

    // Steps 3 - 6: Attempt to break unknown string.
    // TODO: feed char into oracle until the first block returned doesn't
    // change, indicating that the number of chars filled should be the prefix
    // "padding". Subsequently pad with these characters and continue with algo
    // as in challenge 12
    let total_block_count = encryption_oracle(&padding, &key).len() / block_size;
    let random_prefix_block_count = block_position + 1;
    let mut input: Vec<u8> = (0..block_size).into_iter().map(|_| b'A').collect();
    let mut message = Vec::new();
    for block in random_prefix_block_count..total_block_count {
        for i in 0..block_size {
            // Step 4: Create dictionary for every possible last byte.
            let mut map = HashMap::new();
            let mut input_block = input.clone();
            for ascii_code in 0..=127 {
                input_block[block_size - 1] = ascii_code;
                let ciphertext =
                    encryption_oracle(&[padding.clone(), input_block.clone()].concat(), &key);
                let target_block = &ciphertext[random_prefix_block_count * block_size
                    ..(random_prefix_block_count + 1) * block_size];
                map.insert(target_block.to_vec(), ascii_code);
            }

            // Step 5: Attempt to match output to one of the dict entries above.
            let crafted_input = &input[0..block_size - i - 1];
            let ciphertext = encryption_oracle(&[&padding, crafted_input].concat(), &key);
            let target_block = &ciphertext[(block * block_size)..((block + 1) * block_size)];
            let ascii_code = *(map.get(target_block).expect("to match an ascii code"));

            println!("{block}[{:>2}]: {ascii_code}", i);
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

// TODO: explore storing random prefix in a global var first, then later see if
// there are OOP or "Rust" approaches to this
fn encryption_oracle(input: &[u8], key: &[u8]) -> Vec<u8> {
    // let mut rng = rand::thread_rng();
    // random_prefix = Some(generate_random_bytes(rng.gen::<u8>() as usize));
    let random_prefix = "random".as_bytes();

    let unknown = general_purpose::STANDARD
        .decode(UNKNOWN_STRING.replace("\n", ""))
        .unwrap();

    let message = [random_prefix, &Vec::from(input), &unknown].concat();

    let ciphertext = ecb_encrypt(&message, &key);
    // println!("{:-^64}", "CIPHERTEXT");
    // for chunk in ciphertext.chunks(16) {
    //     println!("{:2x?}", chunk);
    // }
    ciphertext
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

fn find_block_size(key: &[u8]) -> Option<usize> {
    let mut block_size = None;
    let mut last_length = None;
    for i in 0..16 {
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

// fn find_first_block(ciphertext: &[u8], block_size: usize) -> &[u8] {
//     for chunk in ciphertext.chunks(block_size) {
//         println!("{:2x?}", chunk);
//     }
// }

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
