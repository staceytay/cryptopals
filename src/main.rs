use aes::cipher::{
    generic_array::{typenum::U16, GenericArray},
    BlockDecrypt, BlockEncrypt, KeyInit,
};
use aes::Aes128;
use rand::Rng;
use std::collections::HashMap;
use url::Url;

fn main() {
    let key = generate_random_bytes(16);

    let encoded = "foo=bar&baz=qux&zap=zazzle";
    println!("{:?}", decode(encoded));

    let example_encoded = "email=abc@email.com&uid=10&role=user";

    assert_eq!(example_encoded, profile_for("&=abc&@email.com"));
    assert_eq!(
        example_encoded,
        String::from_utf8(ecb_decrypt(
            &ecb_encrypt(profile_for("abc@email.com").as_bytes(), &key),
            &key
        ))
        .unwrap()
    );

    let ciphertext = [
        // The chosen input here would produce a ciphertext with three blocks
        // and the last block would be
        // "user\u{c}\u{c}\u{c}\u{c}\u{c}\u{c}\u{c}\u{c}\u{c}\u{c}\u{c}\u{c}".
        // We take the first two blocks of this ciphertext.
        &ecb_encrypt(profile_for("admin@bar.com").as_bytes(), &key)[..32],
        // The chosen input here would produce a ciphertext with the second
        // block being
        // "admin\u{b}\u{b}\u{b}\u{b}\u{b}\u{b}\u{b}\u{b}\u{b}\u{b}\u{b}". We
        // append this block to the previous two blocks above to form our
        // desired role=admin profile.
        &ecb_encrypt(
            profile_for(
                "1234567890admin\u{b}\u{b}\u{b}\u{b}\u{b}\u{b}\u{b}\u{b}\u{b}\u{b}\u{b}\u{b}",
            )
            .as_bytes(),
            &key,
        )[16..32],
    ]
    .concat();

    assert_eq!(
        "email=admin@bar.com&uid=10&role=admin",
        String::from_utf8(ecb_decrypt(&ciphertext, &key)).unwrap()
    );
}

fn decode(encoded: &str) -> HashMap<String, String> {
    // Use url just to leverage the query string parsing code.
    let url = Url::parse(&format!("https://example.net?{}", encoded)).unwrap();
    let map: HashMap<_, _> = url.query_pairs().into_owned().collect();
    map
}

fn profile_for(email: &str) -> String {
    let validated_email: String = email.chars().filter(|c| !"&=".contains(*c)).collect();
    format!("email={}&uid=10&role=user", validated_email)
}

fn ecb_decrypt(bytes: &[u8], key: &[u8]) -> Vec<u8> {
    let key = GenericArray::<u8, U16>::clone_from_slice(key);
    let cipher = Aes128::new(&key);

    let block_size = 16;
    let mut message = Vec::new();
    for i in 0..(bytes.len() / block_size) {
        let mut block = GenericArray::<u8, U16>::clone_from_slice(
            &bytes[(i * block_size)..((i + 1) * block_size)],
        );
        cipher.decrypt_block(&mut block);
        if block[15] < 16u8 {
            // Trim off padding for the last block.
            message.extend(&block[..16 - block[15] as usize])
        } else {
            message.extend(block)
        }
    }
    message
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
