use aes::cipher::{
    generic_array::{typenum::U16, GenericArray},
    BlockDecrypt, BlockEncrypt, KeyInit,
};
use aes::Aes128;
use rand::Rng;

const KEY_LENGTH: usize = 16;

fn main() {
    let oracle = Oracle::new();
    let (ciphertext, iv) = oracle.encrypt();
    // println!("{:?}", ciphertext);
    // println!("{:?}", oracle.decrypt(&ciphertext[0..32], &iv));

    let block_size = 16;
    let mut plaintext: Vec<u8> = Vec::new();
    for block_index in 0..(ciphertext.len() / block_size) {
        // for block_index in 0..1 {
        let mut intermediate_block = vec![0; block_size];
        for i in 1..=block_size {
            // println!("LOOP bi = {block_index}, i = {i}");
            let mut tampered_block = vec![0; block_size];
            for j in 1..=i {
                tampered_block[block_size - j] = i as u8;
            }
            // TODO: how to prepare tempered block here to be a zeroing IV?

            // println!(
            //     "INTERMEDIATE BLOCK: {block_index}: {i}: {:?}",
            //     intermediate_block
            // );
            // println!("TAMPERED BLOCK: {:?}", tampered_block);
            tampered_block = fixed_xor(&tampered_block, &intermediate_block);
            // println!("TAMPERED BLOCK after XOR: {:?}", tampered_block);
            for code in u8::MIN..=u8::MAX {
                tampered_block[block_size - i] = code;
                // println!("TAMPERED BLOCK with code = {code}: {:?}", tampered_block);
                let valid = oracle.decrypt(
                    &ciphertext[block_index * block_size..(block_index + 1) * block_size],
                    &tampered_block,
                );
                if valid {
                    // println!("VALID FIRST bi = {block_index}, i = {i}, code = {code}");
                    if i == 1 {
                        tampered_block[block_size - i - 1] = 22u8;
                        let valid2 = oracle.decrypt(
                            &ciphertext[block_index * block_size..(block_index + 1) * block_size],
                            &tampered_block,
                        );
                        if valid2 {
                            // println!("VALID SECOND bi = {block_index}, i = {i}, code = {code}");
                            // let intermediate_code =
                            //     i as u8 ^ ciphertext[(block_index * block_size) + (block_size - i)];
                            intermediate_block[block_size - i] = code ^ i as u8;
                            break;
                        }
                        tampered_block[block_size - i - 1] = 0u8;
                    } else {
                        // let intermediate_code =
                        //     i as u8 ^ ciphertext[(block_index * block_size) + (block_size - i)];
                        intermediate_block[block_size - i] = code ^ i as u8;
                        break;
                    }
                    // println!(
                    //     "INTERMEDIATE BLOCK: {block_index}: {i}: {:?}",
                    //     intermediate_block
                    // );
                    // println!("{:-^64}", "END");
                }
            }
            // println!(
            //     "INTERMEDIATE BLOCK: {block_index}: {i}: {:?}",
            //     intermediate_block
            // );
        }
        let previous_ciphertext_block = if block_index == 0 {
            &iv
        } else {
            &ciphertext[(block_index - 1) * block_size..block_index * block_size]
        };
        let plaintext_block = fixed_xor(previous_ciphertext_block, &intermediate_block);
        println!("Plaintext BLOCK: {:?}", plaintext_block);
        plaintext.extend(plaintext_block);
    }

    println!("{:-^64}", "CIPHERTEXT");
    println!("{:?}", ciphertext);
    println!("{:-^64}", "PLAINTEXT");
    println!("{:?}", plaintext);
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
        println!("{:-^64}", "SELECTED STRING");
        println!("{:?}", selected_string.as_bytes());
        println!("{:-^64}", "END");

        let ciphertext = cbc_encrypt(&iv, &self.key, selected_string.as_bytes());
        (ciphertext, iv)
    }

    fn decrypt(&self, ciphertext: &[u8], iv: &[u8]) -> bool {
        let message = cbc_decrypt(iv, &self.key, ciphertext);
        // println!("{:-^64}", "DECRYPTED MESSAGE");
        // println!("{:?}", message);
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

fn cbc_encrypt(iv: &[u8], key: &[u8], bytes: &[u8]) -> Vec<u8> {
    let key = GenericArray::<u8, U16>::clone_from_slice(key);
    let cipher = Aes128::new(&key);

    let block_size = 16;
    let mut ciphertext = Vec::new();
    let mut previous_block = iv.to_vec();

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

fn validate_pkcs7pad(plaintext: &[u8]) -> Result<(), &'static str> {
    let padding_length = *plaintext.last().unwrap();
    if padding_length == 0 {
        return Err("invalid padding character");
    }
    for i in 1..=padding_length {
        if plaintext[plaintext.len() - i as usize] != padding_length {
            return Err("invalid padding character");
        }
    }
    Ok(())
}
