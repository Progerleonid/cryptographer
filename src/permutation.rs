use zeroize::Zeroize;

// These constants are public, fixed parts of the algorithm. They are not keys or secrets.
pub const INITIAL_CONSTANTS: [u64; 16] = [
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

const MULTIPLIERS: [u64; 16] = [
    0x9e37_79b1_85eb_ca87,
    0xc2b2_ae3d_27d4_eb4f,
    0x1656_67b1_9e37_79f9,
    0x85eb_ca77_c2b2_ae63,
    0x27d4_eb2f_1656_67c5,
    0x94d0_49bb_1331_11eb,
    0xd6e8_feb8_6659_fd93,
    0xa5a3_564e_27f8_864d,
    0x8cb9_2baa_72f3_d8dd,
    0xdb4f_0b91_75ae_2165,
    0xbb67_ae85_84ca_a73b,
    0x6a09_e667_f3bc_c909,
    0x3c6e_f372_fe94_f82b,
    0xa54f_f53a_5f1d_36f1,
    0x510e_527f_ade6_82d1,
    0x1f83_d9ab_fb41_bd6b,
];

const EVEN_PERMUTATION: [usize; 16] = [5, 10, 15, 0, 9, 14, 3, 8, 13, 2, 7, 12, 1, 6, 11, 4];
const ODD_PERMUTATION: [usize; 16] = [11, 4, 13, 6, 15, 8, 1, 10, 3, 12, 5, 14, 7, 0, 9, 2];
const DIAGONALS: [[usize; 4]; 4] = [[0, 5, 10, 15], [1, 6, 11, 12], [2, 7, 8, 13], [3, 4, 9, 14]];

pub struct ObsidianState {
    lanes: [u64; 16],
}

impl ObsidianState {
    #[must_use]
    pub fn from_lanes(lanes: [u64; 16]) -> Self {
        Self { lanes }
    }

    #[must_use]
    pub fn initialized() -> Self {
        Self::from_lanes(INITIAL_CONSTANTS)
    }

    #[must_use]
    pub fn lanes(&self) -> &[u64; 16] {
        &self.lanes
    }

    pub(crate) fn lanes_mut(&mut self) -> &mut [u64; 16] {
        &mut self.lanes
    }
}

impl Drop for ObsidianState {
    fn drop(&mut self) {
        self.lanes.zeroize();
    }
}

pub fn permute(state: &mut ObsidianState, rounds: usize) {
    for round in 0..rounds {
        let round_word = (round as u64).wrapping_add(1);

        for (index, constant) in INITIAL_CONSTANTS.iter().copied().enumerate() {
            let rotation = ((index * 7 + round * 3) % 63 + 1) as u32;
            let injection = constant
                .wrapping_add(round_word.wrapping_mul(0x9e37_79b9_7f4a_7c15))
                .wrapping_add((index as u64).wrapping_mul(0xd1b5_4a32_d192_ed03))
                .rotate_left(rotation);
            state.lanes[index] = state.lanes[index].wrapping_add(injection);
        }

        for (pair, multiplier) in MULTIPLIERS.iter().copied().take(8).enumerate() {
            let left_index = pair * 2;
            let right_index = left_index + 1;
            let rotation_left = ((pair * 9 + round * 5) % 63 + 1) as u32;
            let rotation_right = ((pair * 13 + round * 7 + 17) % 63 + 1) as u32;
            let mut left = state.lanes[left_index];
            let mut right = state.lanes[right_index];
            left = left.wrapping_add(right);
            right ^= left.rotate_left(rotation_left);
            right = right.wrapping_mul(multiplier);
            left ^= right.rotate_left(rotation_right);
            state.lanes[left_index] = left;
            state.lanes[right_index] = right;
        }

        for (group_index, group) in DIAGONALS.iter().enumerate() {
            let a = state.lanes[group[0]];
            let b = state.lanes[group[1]];
            let c = state.lanes[group[2]];
            let d = state.lanes[group[3]];
            let base = (round + group_index * 11) as u32;
            state.lanes[group[0]] = a.wrapping_add(b).rotate_left(base % 63 + 1) ^ d;
            state.lanes[group[1]] = b.wrapping_add(c).rotate_left((base + 17) % 63 + 1) ^ a;
            state.lanes[group[2]] = c.wrapping_add(d).rotate_left((base + 31) % 63 + 1) ^ b;
            state.lanes[group[3]] = d.wrapping_add(a).rotate_left((base + 47) % 63 + 1) ^ c;
        }

        for (index, base_multiplier) in MULTIPLIERS.iter().copied().enumerate() {
            let multiplier = base_multiplier
                .wrapping_add(round_word.wrapping_mul(2))
                .wrapping_add((index as u64).wrapping_mul(2));
            let transformed = state.lanes[index].wrapping_mul(multiplier);
            let high_rotation = ((index * 5 + round * 11) % 63 + 1) as u32;
            let low_rotation = ((index * 3 + round * 13 + 29) % 63 + 1) as u32;
            state.lanes[index] = transformed
                ^ transformed.rotate_left(high_rotation)
                ^ transformed.rotate_right(low_rotation);
        }

        let table = if round % 2 == 0 {
            &EVEN_PERMUTATION
        } else {
            &ODD_PERMUTATION
        };
        let old = state.lanes;
        for (destination, source) in table.iter().copied().enumerate() {
            state.lanes[destination] = old[source];
        }
    }
}
