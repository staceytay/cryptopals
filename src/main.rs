use std::collections::HashMap;
use std::num::ParseIntError;

const FILE: &'static str = include_str!("../4.txt");

const CHARS: &'static str = "ETAOIN SHRDLU";

fn main() {
    for (i, line) in FILE.lines().enumerate() {
        let bts = decode_hex(line).unwrap();

        // Get most frequently appearing byte as before.
        let mut counts = HashMap::new();
        for b in bts.iter() {
            *counts.entry(b).or_insert(0) += 1;
        }

        let frequentest = counts.iter().max_by_key(|(_, v)| *v).unwrap();

        // No point considering "most frequent" characters that actually only
        // appear once.
        if *frequentest.1 > 1 {
            for c in CHARS.chars() {
                let key = c as u8 ^ **frequentest.0;
                let decoded = show(
                    &bts.clone()
                        .into_iter()
                        .map(|b| b ^ key)
                        .collect::<Vec<u8>>()[..],
                );

                // Count most frequently appearing character.
                let mut counts = HashMap::new();
                for c in decoded.chars() {
                    *counts.entry(c).or_insert(0) += 1;
                }
                let frequentest = counts.iter().max_by_key(|(_, v)| *v).unwrap();

                // Use this heuristic to see if the string is likely to be the
                // message. Heuristic: most frequent char in `decoded` should be
                // from set in `CHARS` and there should be a space considering
                // the length of the message.
                if CHARS.contains(*frequentest.0) && decoded.contains(" ") {
                    println!("[L{:03}]: [{}] -> {}", i, c, decoded);
                }
            }
        }
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
