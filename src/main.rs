const N: usize = 624;
const M: usize = 397;

fn main() {
    let mut rand0 = MT19937::new(rand::random::<u32>());

    // Clone rand0's state.
    let mut state = [0; N];
    for i in 0..N {
        state[i] = untemper(rand0.gen());
    }
    let mut rand1 = MT19937::splice(state);

    // Check that the spliced generator rand1 predicts the output of rand0.
    for _ in 0..4096 {
        assert_eq!(rand0.gen(), rand1.gen());
    }
}

// Referenced from
// https://gist.github.com/Rhomboid/b1a882c70b7a1901efa9#file-mersenne_predict-py-L77.
fn untemper(x: u32) -> u32 {
    fn undo_xor_rshift(x: u32, shift: usize) -> u32 {
        // Reverses the operation x ^= (x >> shift).
        let mut result = x;
        for shift_amount in (shift..32).step_by(shift) {
            result ^= x >> shift_amount;
        }
        result
    }

    fn undo_xor_lshiftmask(mut x: u32, shift: usize, mask: u32) -> u32 {
        // Reverses the operation x ^= ((x << shift) & mask).
        let mut window = (1 << shift) - 1;
        for _ in 0..(32 / shift) {
            x ^= ((window & x) << shift) & mask;
            window <<= shift;
        }
        x
    }

    let mut y = x;
    y = undo_xor_rshift(y, 18);
    y = undo_xor_lshiftmask(y, 15, 4022730752);
    y = undo_xor_lshiftmask(y, 7, 2636928640);
    y = undo_xor_rshift(y, 11);
    y
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

    fn splice(state: [u32; N]) -> MT19937 {
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
