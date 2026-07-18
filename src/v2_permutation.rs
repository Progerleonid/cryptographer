use zeroize::Zeroize;

pub const P1024_V2_ROUNDS: usize = 32;

const INITIAL_STATE: [u64; 16] = [
    0x243f_6a88_85a3_08d3,
    0x1319_8a2e_0370_7344,
    0xa409_3822_299f_31d0,
    0x082e_fa98_ec4e_6c89,
    0x4528_21e6_38d0_1377,
    0xbe54_66cf_34e9_0c6c,
    0xc0ac_29b7_c97c_50dd,
    0x3f84_d5b5_b547_0917,
    0x9216_d5d9_8979_fb1b,
    0xd131_0ba6_98df_b5ac,
    0x2ffd_72db_d01a_dfb7,
    0xb8e1_afed_6a26_7e96,
    0xba7c_9045_f12c_7f99,
    0x24a1_9947_b391_6cf7,
    0x0801_f2e2_858e_fc16,
    0x6369_20d8_7157_4e69,
];

const ROUND_MULTIPLIERS: [u64; 8] = [
    0x9e37_79b1_85eb_ca87,
    0xc2b2_ae3d_27d4_eb4f,
    0x1656_67b1_9e37_79f9,
    0x85eb_ca77_c2b2_ae63,
    0x27d4_eb2f_1656_67c5,
    0x94d0_49bb_1331_11eb,
    0xd6e8_feb8_6659_fd93,
    0xa5a3_564e_27f8_864d,
];

const ROTATIONS: [u32; 8] = [7, 19, 31, 43, 53, 11, 37, 59];
const SHUFFLE: [usize; 8] = [2, 5, 1, 7, 3, 0, 6, 4];

pub struct P1024V2 {
    lanes: [u64; 16],
}

impl P1024V2 {
    #[must_use]
    pub fn initialized() -> Self {
        Self {
            lanes: INITIAL_STATE,
        }
    }

    #[cfg(test)]
    #[must_use]
    pub fn from_lanes(lanes: [u64; 16]) -> Self {
        Self { lanes }
    }

    #[must_use]
    pub fn lanes(&self) -> &[u64; 16] {
        &self.lanes
    }

    pub fn lanes_mut(&mut self) -> &mut [u64; 16] {
        &mut self.lanes
    }
}

impl Drop for P1024V2 {
    fn drop(&mut self) {
        self.lanes.zeroize();
    }
}

fn round_function(right: &[u64; 8], round: usize) -> [u64; 8] {
    let mut words = *right;
    let round_word = (round as u64).wrapping_add(1);
    for step in 0..4 {
        for index in 0..8 {
            let neighbour = (index + 1) % 8;
            let target = (index + 3) % 8;
            let rotation = ROTATIONS[(index + step) % 8];
            let injection = INITIAL_STATE[(index + round + step) % 16]
                .wrapping_add(round_word.wrapping_mul(0x9e37_79b9_7f4a_7c15))
                .rotate_left(((round + index * 7 + step * 13) % 63 + 1) as u32);
            words[index] = words[index]
                .wrapping_add(words[neighbour].rotate_left(rotation))
                .wrapping_add(injection)
                .wrapping_mul(ROUND_MULTIPLIERS[(index + step) % 8]);
            words[target] ^= words[index].rotate_left(ROTATIONS[(index + step + 3) % 8]);
        }
        let old = words;
        for (destination, source) in SHUFFLE.iter().copied().enumerate() {
            words[destination] = old[source];
        }
    }
    words
}

pub fn permute(state: &mut P1024V2) {
    for round in 0..P1024_V2_ROUNDS {
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

#[cfg(test)]
pub fn inverse_permute(state: &mut P1024V2) {
    for round in (0..P1024_V2_ROUNDS).rev() {
        let mut new_left = [0_u64; 8];
        let mut new_right = [0_u64; 8];
        new_left.copy_from_slice(&state.lanes[..8]);
        new_right.copy_from_slice(&state.lanes[8..]);
        let function = round_function(&new_left, round);
        for index in 0..8 {
            state.lanes[index] = new_right[index] ^ function[index];
            state.lanes[index + 8] = new_left[index];
        }
        new_left.zeroize();
        new_right.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::{P1024V2, inverse_permute, permute};

    #[test]
    fn permutation_has_a_working_inverse() {
        let mut seed = 0x1234_5678_9abc_def0_u64;
        for _ in 0..1_000 {
            let mut lanes = [0_u64; 16];
            for lane in &mut lanes {
                seed ^= seed << 13;
                seed ^= seed >> 7;
                seed ^= seed << 17;
                *lane = seed;
            }
            let original = lanes;
            let mut state = P1024V2::from_lanes(lanes);
            permute(&mut state);
            inverse_permute(&mut state);
            assert_eq!(state.lanes(), &original);
        }
    }

    #[test]
    fn one_bit_change_has_regression_avalanche() {
        let baseline = [0_u64; 16];
        let mut baseline_state = P1024V2::from_lanes(baseline);
        permute(&mut baseline_state);
        let baseline_output = *baseline_state.lanes();
        let mut total = 0_u64;
        for bit in 0..128 {
            let mut changed = baseline;
            changed[bit / 64] ^= 1_u64 << (bit % 64);
            let mut changed_state = P1024V2::from_lanes(changed);
            permute(&mut changed_state);
            total += baseline_output
                .iter()
                .zip(changed_state.lanes())
                .map(|(left, right)| u64::from((left ^ right).count_ones()))
                .sum::<u64>();
        }
        assert!(total / 128 >= 400);
    }

    #[test]
    fn fixed_vector_defines_p1024_v2() {
        let mut state = P1024V2::from_lanes([0_u64; 16]);
        permute(&mut state);
        assert_eq!(
            state.lanes(),
            &[
                0xb20d_33f9_2e11_dadb,
                0x9e57_a39b_4685_219c,
                0x26f5_c846_bfbe_8e75,
                0x6190_7192_d85e_2af2,
                0x4fe9_cd78_2127_e0ac,
                0xc109_f92d_27eb_f6cd,
                0xf33f_463a_7799_e342,
                0x75ac_bb50_80fe_b69e,
                0x2184_c7ca_6ba6_3f3b,
                0x3b9d_8c1c_6acf_39e5,
                0x39a9_2762_552d_7d94,
                0x79e7_cafc_6189_2a41,
                0x5ab2_da76_abf1_9bf2,
                0x2500_7b6c_e49d_e8a5,
                0xbd2a_a10d_e6a4_5970,
                0x52a8_19e7_20e2_5e8e,
            ]
        );
    }
}
