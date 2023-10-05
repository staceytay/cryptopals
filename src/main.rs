use base64::{engine::general_purpose, Engine as _};
use std::collections::HashMap;

const CHARS: &'static str = "ETAOINetaoin SHRDLUshrdlu";
const FILE: &'static str = include_str!("../6.txt");

fn main() {
    assert_eq!(
        edit_distance("this is a test".as_bytes(), "wokka wokka!!!".as_bytes()),
        37
    );

    let bytes = general_purpose::STANDARD
        .decode(FILE.replace('\n', ""))
        .unwrap();

    // Calculate edit distance for each KEYSIZE averaging over n comparisons.
    let comparisons = 32;
    println!("Edit distance (avg) comparing {comparisons} blocks");
    for i in 2..40 {
        let mut sum = 0.0;
        for j in 0..(comparisons * 2) {
            if j % 2 == 0 {
                sum += f64::from(edit_distance(
                    &bytes[((j + 0) * i)..((j + 1) * i)],
                    &bytes[((j + 1) * i)..((j + 2) * i)],
                )) / i as f64;
            }
        }

        println!("KEYSIZE = {:02}: {}", i, sum / comparisons as f64);
    }
    println!("");

    let keysize = 29; // Based on results above.
    let mut key = vec![0; keysize];
    for i in 0..keysize {
        // Transpose the original cipher text according to our predicted
        // keysize.
        let cipher: Vec<u8> = bytes
            .iter()
            .enumerate()
            .filter_map(|(j, &b)| if j % keysize == i { Some(b) } else { None })
            .collect();

        // Count the frequency of each letter.
        let mut counts = HashMap::new();
        for b in cipher.iter() {
            *counts.entry(b).or_insert(0) += 1;
        }

        // Get a sorted (in reversed order) list of the most frequently used
        // characters. From
        // https://stackoverflow.com/questions/34555837/sort-hashmap-data-by-value
        let mut counts_vec: Vec<_> = counts.iter().collect();
        counts_vec.sort_by(|a, b| b.1.cmp(a.1));

        // Store our best guess at which key is the one. First value is the sum
        // of occurences of the letters of the alphabet (in both lower and
        // uppercase) and the space char. Second value is the corresponding key.
        let mut best_guess = (0.0, 0);
        for c in CHARS.chars() {
            let k = c as u8 ^ **counts_vec[0].0;
            let message = &cipher
                .clone()
                .into_iter()
                .map(|b| b ^ k)
                .collect::<Vec<u8>>()[..];

            // Count freq of each ASCII char appearing.
            let mut freq = HashMap::new();
            for b in message.iter() {
                *freq.entry(b).or_insert(0.0) += 1.0;
            }

            for (_, v) in freq.iter_mut() {
                *v /= cipher.len() as f64;
            }
            let mut sum_occurences = 0.0;
            for i in 32..=122 {
                // If i is either the space char or a letter of the
                // alphabet(-ish).
                if i == 32 || i > 64 {
                    match freq.get(&i) {
                        Some(v) => sum_occurences += v,
                        None => (),
                    }
                }
            }

            // At least 80% of characters should be letters of the alphabet or
            // space.
            if sum_occurences > 0.8 && sum_occurences > best_guess.0 {
                best_guess.0 = sum_occurences;
                best_guess.1 = k;
            }
        }
        key[i] = best_guess.1;
    }
    println!("{:-^64}", "KEY");
    println!("{}", show(&key));
    let message = repeat_xor(&key, &bytes);
    println!("{:-^64}", "MESSAGE");
    println!("{}", String::from_utf8_lossy(&message));
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

fn repeat_xor(k: &[u8], m: &[u8]) -> Vec<u8> {
    let mut bs = Vec::new();
    for (i, b) in m.iter().enumerate() {
        bs.push(b ^ k[i % k.len()]);
    }
    bs
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
