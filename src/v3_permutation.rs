use zeroize::Zeroize;

pub const P1024_V3_ROUNDS: usize = 48;

const MULTIPLIERS: [u64; 8] = [
    0x9e37_79b1_85eb_ca87,
    0xc2b2_ae3d_27d4_eb4f,
    0x1656_67b1_9e37_79f9,
    0x85eb_ca77_c2b2_ae63,
    0x27d4_eb2f_1656_67c5,
    0x94d0_49bb_1331_11eb,
    0xd6e8_feb8_6659_fd93,
    0xa5a3_564e_27f8_864d,
];

const ADD_ROTATIONS: [[u32; 8]; 4] = [
    [7, 19, 31, 43, 53, 11, 37, 59],
    [13, 29, 47, 61, 17, 41, 23, 51],
    [5, 27, 39, 57, 15, 33, 49, 21],
    [11, 35, 55, 25, 45, 9, 63, 17],
];

const DIFFUSION_ROTATIONS: [[u32; 4]; 4] = [
    [23, 30, 29, 31],
    [5, 30, 25, 4],
    [61, 52, 9, 29],
    [53, 48, 47, 50],
];

const SHUFFLES: [[usize; 8]; 4] = [
    [2, 5, 1, 7, 3, 0, 6, 4],
    [6, 2, 7, 1, 4, 3, 0, 5],
    [3, 7, 4, 0, 6, 2, 5, 1],
    [5, 0, 3, 6, 1, 7, 4, 2],
];

/// Public, deterministic constant generation. The constants are not secret and
/// are derived only from the V3 seed and their position.
#[must_use]
pub fn round_constant(round: usize, step: usize, lane: usize) -> u64 {
    let mut value = 0x4f42_5349_4449_414e_u64
        ^ (round as u64).wrapping_mul(0x9e37_79b9_7f4a_7c15)
        ^ (step as u64).wrapping_mul(0xd1b5_4a32_d192_ed03)
        ^ (lane as u64).wrapping_mul(0x94d0_49bb_1331_11eb);
    value ^= value.rotate_left(17) ^ value.rotate_right(11);
    value = value.wrapping_mul(0xd6e8_feb8_6659_fd93);
    value ^= value >> 29;
    value = value.wrapping_mul(0xa5a3_564e_27f8_864d);
    value ^ value.rotate_left(((round + step * 13 + lane * 7) % 63 + 1) as u32)
}

pub struct P1024V3 {
    lanes: [u64; 16],
}

impl P1024V3 {
    #[must_use]
    pub fn initialized() -> Self {
        let mut lanes = [0_u64; 16];
        for (lane, value) in lanes.iter_mut().enumerate() {
            *value = round_constant(P1024_V3_ROUNDS, 4, lane);
        }
        Self { lanes }
    }

    #[must_use]
    pub fn from_lanes(lanes: [u64; 16]) -> Self {
        Self { lanes }
    }

    #[must_use]
    pub fn lanes(&self) -> &[u64; 16] {
        &self.lanes
    }

    pub(crate) fn lanes_mut(&mut self) -> &mut [u64; 16] {
        &mut self.lanes
    }
}

impl Drop for P1024V3 {
    fn drop(&mut self) {
        self.lanes.zeroize();
    }
}

fn nonlinear_layer(words: &[u64; 8], round: usize, step: usize) -> [u64; 8] {
    let mut mixed = [0_u64; 8];
    for index in 0..8 {
        let neighbour = words[(index + 1) % 8].rotate_left(ADD_ROTATIONS[step][index]);
        let cross = words[(index + 4) % 8].rotate_left(ADD_ROTATIONS[step][(index + 3) % 8]);
        mixed[index] = words[index]
            .wrapping_add(neighbour)
            .wrapping_add(round_constant(round, step, index))
            .wrapping_mul(MULTIPLIERS[(index + step) % 8])
            ^ cross;
    }
    mixed
}

fn diffusion_layer(words: &[u64; 8], step: usize) -> [u64; 8] {
    let rotations = DIFFUSION_ROTATIONS[step];
    let mut diffused = [0_u64; 8];
    for index in 0..8 {
        diffused[index] = words[index]
            ^ words[(index + 1) % 8].rotate_left(rotations[0])
            ^ words[(index + 3) % 8].rotate_left(rotations[1])
            ^ words[(index + 5) % 8].rotate_left(rotations[2])
            ^ words[(index + 6) % 8].rotate_left(rotations[3]);
    }
    let mut shuffled = [0_u64; 8];
    for (destination, source) in SHUFFLES[step].iter().copied().enumerate() {
        shuffled[destination] = diffused[source];
    }
    shuffled
}

fn round_function(right: &[u64; 8], round: usize) -> [u64; 8] {
    let mut words = *right;
    for step in 0..4 {
        words = nonlinear_layer(&words, round, step);
        words = diffusion_layer(&words, step);
    }
    words
}

pub fn permute_rounds(state: &mut P1024V3, rounds: usize) {
    assert!(rounds <= P1024_V3_ROUNDS);
    for round in 0..rounds {
        let mut left = [0_u64; 8];
        let mut right = [0_u64; 8];
        left.copy_from_slice(&state.lanes[..8]);
        right.copy_from_slice(&state.lanes[8..]);
        let function = round_function(&right, round);
        for index in 0..8 {
            state.lanes[index] = right[index];
            state.lanes[index + 8] = left[index] ^ function[index];
        }
        left.zeroize();
        right.zeroize();
    }
}

pub fn permute(state: &mut P1024V3) {
    permute_rounds(state, P1024_V3_ROUNDS);
}

#[cfg(test)]
fn inverse_permute(state: &mut P1024V3) {
    for round in (0..P1024_V3_ROUNDS).rev() {
        let mut new_left = [0_u64; 8];
        let mut new_right = [0_u64; 8];
        new_left.copy_from_slice(&state.lanes[..8]);
        new_right.copy_from_slice(&state.lanes[8..]);
        let function = round_function(&new_left, round);
        for index in 0..8 {
            state.lanes[index] = new_right[index] ^ function[index];
            state.lanes[index + 8] = new_left[index];
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        DIFFUSION_ROTATIONS, P1024V3, diffusion_layer, inverse_permute, permute, round_constant,
    };

    fn highest_bit(value: &[u64; 8]) -> Option<usize> {
        for lane in (0..8).rev() {
            if value[lane] != 0 {
                return Some(lane * 64 + 63 - value[lane].leading_zeros() as usize);
            }
        }
        None
    }

    fn diffusion_rank(step: usize) -> usize {
        let mut basis: [Option<[u64; 8]>; 512] = [None; 512];
        let mut rank = 0;
        for bit in 0..512 {
            let mut input = [0_u64; 8];
            input[bit / 64] = 1_u64 << (bit % 64);
            let mut vector = diffusion_layer(&input, step);
            while let Some(pivot) = highest_bit(&vector) {
                if let Some(existing) = basis[pivot] {
                    for lane in 0..8 {
                        vector[lane] ^= existing[lane];
                    }
                } else {
                    basis[pivot] = Some(vector);
                    rank += 1;
                    break;
                }
            }
        }
        rank
    }

    #[test]
    fn permutation_has_a_working_inverse() {
        let mut seed = 0x1234_5678_9abc_def0_u64;
        for _ in 0..256 {
            let mut lanes = [0_u64; 16];
            for lane in &mut lanes {
                seed ^= seed << 13;
                seed ^= seed >> 7;
                seed ^= seed << 17;
                *lane = seed;
            }
            let original = lanes;
            let mut state = P1024V3::from_lanes(lanes);
            permute(&mut state);
            inverse_permute(&mut state);
            assert_eq!(state.lanes(), &original);
        }
    }

    #[test]
    fn positional_round_constants_are_distinct_in_the_used_schedule() {
        let mut constants = std::collections::HashSet::new();
        for round in 0..48 {
            for step in 0..4 {
                for lane in 0..8 {
                    assert!(constants.insert(round_constant(round, step, lane)));
                }
            }
        }
    }

    #[test]
    fn every_diffusion_layer_has_full_binary_rank() {
        for step in 0..DIFFUSION_ROTATIONS.len() {
            assert_eq!(diffusion_rank(step), 512, "diffusion step {step}");
        }
    }

    #[test]
    fn every_single_bit_reaches_both_halves() {
        let mut baseline = P1024V3::from_lanes([0; 16]);
        permute(&mut baseline);
        let baseline = *baseline.lanes();
        for bit in 0..1024 {
            let mut input = [0_u64; 16];
            input[bit / 64] = 1_u64 << (bit % 64);
            let mut changed = P1024V3::from_lanes(input);
            permute(&mut changed);
            let left = baseline[..8]
                .iter()
                .zip(&changed.lanes()[..8])
                .map(|(a, b)| (a ^ b).count_ones())
                .sum::<u32>();
            let right = baseline[8..]
                .iter()
                .zip(&changed.lanes()[8..])
                .map(|(a, b)| (a ^ b).count_ones())
                .sum::<u32>();
            assert!(
                left >= 160 && right >= 160,
                "weak diffusion for input bit {bit}"
            );
        }
    }

    #[test]
    fn fixed_vector_defines_p1024_v3() {
        let mut state = P1024V3::from_lanes([0; 16]);
        permute(&mut state);
        assert_eq!(
            state.lanes(),
            &[
                0x7fe2_d357_055f_8320,
                0x62c4_ecb1_2135_ecdd,
                0xd1ed_959a_c297_d6df,
                0x1001_183a_8906_549d,
                0x8e54_4f21_9b76_a64d,
                0xa111_3114_fca5_fb20,
                0xc040_3da1_5da6_eec8,
                0x8b09_dd05_1d66_7511,
                0xa5e0_3cbb_0bdf_a664,
                0xf59c_9d70_2b81_a443,
                0xb885_c14a_f762_7c9d,
                0x924b_b1d2_d950_dfe2,
                0xba4e_0a49_35d1_0f5f,
                0xca56_ec95_1074_78fb,
                0x3c50_75a6_c126_f70e,
                0x2c56_3699_1614_b2f8,
            ]
        );
    }
}
