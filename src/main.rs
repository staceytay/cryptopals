use aes::cipher::{
    generic_array::{typenum::U16, GenericArray},
    BlockEncrypt, KeyInit,
};
use aes::Aes128;
use rand::Rng;

fn main() {
    let ciphertext = encryption_oracle(&vec![64u8; 512]);
    for chunk in ciphertext.chunks(16) {
        println!("{:2x?}", chunk);
    }

    let comparisons = 10;
    let mut sum = 0.0;
    for j in 0..(comparisons * 2) {
        if j % 2 == 0 {
            sum += f64::from(edit_distance(
                &ciphertext[((j + 0) * 16)..((j + 1) * 16)],
                &ciphertext[((j + 1) * 16)..((j + 2) * 16)],
            )) / 16 as f64;
        }
    }

    println!("{:-^64}", "Detected");
    if (sum / comparisons as f64) < 1.0 {
        println!("ECB");
    } else {
        println!("CBC");
    }
    println!("{:-^64}", "");
}

fn encryption_oracle(input: &[u8]) -> Vec<u8> {
    let prefix_count = rand::thread_rng().gen_range(5..=10);
    let suffix_count = rand::thread_rng().gen_range(5..=10);

    let message = [
        generate_random_bytes(prefix_count),
        Vec::from(input),
        generate_random_bytes(suffix_count),
    ]
    .concat();

    let ciphertext;
    println!("{:-^64}", "Using");
    if rand::thread_rng().gen_range(0..2) == 0 {
        println!("ECB");
        ciphertext = ecb_encrypt(&message);
    } else {
        println!("CBC");
        ciphertext = cbc_encrypt(&message);
    }
    println!("{:-^64}", "");
    ciphertext
}

fn ecb_encrypt(bytes: &[u8]) -> Vec<u8> {
    let key = generate_random_bytes(16);
    let key = GenericArray::<u8, U16>::clone_from_slice(&key);

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
