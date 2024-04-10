use rand::Rng;
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const N: usize = 624;
const M: usize = 397;

fn main() {
    thread::sleep(Duration::from_secs(rand::thread_rng().gen_range(40..=1000)));

    let seed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let mut rand = MT19937::new(seed as u32);
    let output = rand.gen();

    thread::sleep(Duration::from_secs(rand::thread_rng().gen_range(40..=1000)));

    let mut guess = None;
    let unix_time = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    for i in 40..=1000 {
        let seed = unix_time as u32 - i;
        let mut rand = MT19937::new(seed);
        if rand.gen() == output {
            guess = Some(seed);
            break;
        }
    }

    match guess {
        None => println!("Seed not found"),
        Some(x) => println!("Seed found: {x}"),
    }
}

struct MT19937 {
    index: usize,
    state: [u32; N],
}

impl MT19937 {
    fn new(seed: u32) -> MT19937 {
        let mut state = [0; N];
        state[0] = seed;
        for i in 1..N {
            state[i] = (1812433253 * (state[i - 1] ^ state[i - 1] >> 30) as u64 + i as u64) as u32;
        }

        MT19937 { index: N, state }
    }

    fn gen(&mut self) -> u32 {
        if self.index >= N {
            for i in 0..N {
                let y = (self.state[i] & 0x80000000) + (self.state[(i + 1) % 624] & 0x7FFFFFFF);
                self.state[i] = self.state[(i + M) % N] ^ y >> 1;

                if y % 2 != 0 {
                    self.state[i] = self.state[i] ^ 0x9908B0DF
                }
            }
            self.index = 0;
        }

        let mut y = self.state[self.index];
        y = y ^ y >> 11;
        y = y ^ y << 7 & 2636928640;
        y = y ^ y << 15 & 4022730752;
        y = y ^ y >> 18;

        self.index = self.index + 1;

        y
    }
}
