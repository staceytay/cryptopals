use std::collections::HashMap;
use std::num::ParseIntError;

fn main() {
    let hex = String::from("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736");
    let bts = decode_hex(&hex).unwrap();
    let mut counts = HashMap::new();
    for b in bts.iter() {
        *counts.entry(b).or_insert(0) += 1;
    }
    println!("{:?}", counts);

    let key = 120 ^ 32;
    println!(
        "{}",
        show(
            &bts.clone()
                .into_iter()
                .map(|b| b ^ key)
                .collect::<Vec<u8>>()[..]
        )
    );

    for i in 32..126 {
        let key = 120 ^ i;
        println!(
            "{}: {:?}",
            i,
            show(
                &bts.clone()
                    .into_iter()
                    .map(|b| b ^ key)
                    .collect::<Vec<u8>>()[..]
            )
        );
    }
}

// From https://stackoverflow.com/questions/52987181/how-can-i-convert-a-hex-string-to-a-u8-slice.
fn decode_hex(s: &str) -> Result<Vec<u8>, ParseIntError> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16))
        .collect()
}

fn fixed_xor(b1: &[u8], b2: &[u8]) -> Vec<u8> {
    b1.into_iter()
        .zip(b2.into_iter())
        .map(|(u1, u2)| u1 ^ u2)
        .collect()
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
