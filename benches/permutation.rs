use std::{
    hint::black_box,
    time::{Duration, Instant},
};

use obsidian_vault::v3_permutation::{P1024V3, permute};

const STATE_BYTES: f64 = 128.0;
const DUPLEX_RATE_BYTES: f64 = 64.0;
const SAMPLES: usize = 11;
const TARGET_SAMPLE_TIME: Duration = Duration::from_millis(250);

fn run(iterations: u64) -> (Duration, u64) {
    let mut state = P1024V3::initialized();
    let start = Instant::now();
    for _ in 0..iterations {
        permute(black_box(&mut state));
    }
    let elapsed = start.elapsed();
    let checksum = state.lanes().iter().fold(0_u64, |sum, lane| sum ^ lane);
    (elapsed, black_box(checksum))
}

fn calibrated_iterations() -> u64 {
    let probe_iterations = 256;
    let (elapsed, _) = run(probe_iterations);
    let elapsed_ns = elapsed.as_nanos().max(1);
    let target_ns = TARGET_SAMPLE_TIME.as_nanos();
    let estimate = (probe_iterations as u128 * target_ns / elapsed_ns) as u64;
    estimate.clamp(1_000, 10_000_000)
}

fn main() {
    // Warm up code and CPU before calibrating the measured samples.
    let _ = run(2_048);
    let iterations = calibrated_iterations();
    let mut ns_per_permutation = Vec::with_capacity(SAMPLES);
    let mut checksum = 0_u64;

    for _ in 0..SAMPLES {
        let (elapsed, sample_checksum) = run(iterations);
        checksum ^= sample_checksum;
        ns_per_permutation.push(elapsed.as_secs_f64() * 1e9 / iterations as f64);
    }

    ns_per_permutation.sort_by(f64::total_cmp);
    let median_ns = ns_per_permutation[SAMPLES / 2];
    let min_ns = ns_per_permutation[0];
    let max_ns = ns_per_permutation[SAMPLES - 1];
    let permutations_per_second = 1e9 / median_ns;
    let state_mb_per_second = permutations_per_second * STATE_BYTES / 1e6;
    let duplex_mb_per_second = permutations_per_second * DUPLEX_RATE_BYTES / 1e6;
    let duplex_mib_per_second = permutations_per_second * DUPLEX_RATE_BYTES / (1024.0 * 1024.0);

    println!("P1024V3 permutation (48 rounds, 1024-bit state)");
    println!("samples: {SAMPLES}, iterations/sample: {iterations}");
    println!("median: {median_ns:.2} ns/permutation");
    println!("range:  {min_ns:.2}..{max_ns:.2} ns/permutation");
    println!("rate:   {permutations_per_second:.2} permutations/s");
    println!("state throughput (128 B/permutation): {state_mb_per_second:.2} MB/s");
    println!("duplex throughput (64 B/permutation): {duplex_mb_per_second:.2} MB/s");
    println!("duplex throughput (binary units):     {duplex_mib_per_second:.2} MiB/s");
    black_box(checksum);
}
