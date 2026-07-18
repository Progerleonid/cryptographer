use std::{env, process::ExitCode};

use obsidian_vault::v3_permutation::{P1024_V3_ROUNDS, P1024V3, permute_rounds};

fn next_word(seed: &mut u64) -> u64 {
    *seed ^= *seed << 13;
    *seed ^= *seed >> 7;
    *seed ^= *seed << 17;
    *seed
}

fn parse_value(arguments: &[String], name: &str, default: usize) -> Result<usize, String> {
    let Some(index) = arguments.iter().position(|argument| argument == name) else {
        return Ok(default);
    };
    let value = arguments
        .get(index + 1)
        .ok_or_else(|| format!("после {name} требуется число"))?;
    value
        .parse::<usize>()
        .map_err(|_| format!("неверное число для {name}: {value}"))
}

fn hamming_distance(left: &[u64; 16], right: &[u64; 16]) -> u32 {
    left.iter()
        .zip(right)
        .map(|(left, right)| (left ^ right).count_ones())
        .sum()
}

fn main() -> ExitCode {
    let arguments: Vec<String> = env::args().collect();
    if arguments.iter().any(|argument| argument == "--help") {
        println!(
            "Использование: cargo run --release --bin analyze_v3 -- [--rounds 48] [--samples 16]"
        );
        return ExitCode::SUCCESS;
    }
    let rounds = match parse_value(&arguments, "--rounds", P1024_V3_ROUNDS) {
        Ok(value @ 1..=P1024_V3_ROUNDS) => value,
        Ok(value) => {
            eprintln!("--rounds должен быть в диапазоне 1..={P1024_V3_ROUNDS}, получено {value}");
            return ExitCode::FAILURE;
        }
        Err(error) => {
            eprintln!("{error}");
            return ExitCode::FAILURE;
        }
    };
    let samples = match parse_value(&arguments, "--samples", 16) {
        Ok(value @ 1..=4_096) => value,
        Ok(value) => {
            eprintln!("--samples должен быть в диапазоне 1..=4096, получено {value}");
            return ExitCode::FAILURE;
        }
        Err(error) => {
            eprintln!("{error}");
            return ExitCode::FAILURE;
        }
    };

    let mut seed = 0x6f62_7369_6469_616e_u64;
    let mut minimum = 1024_u32;
    let mut maximum = 0_u32;
    let mut total = 0_u128;
    let mut derivatives = 0_u128;
    let mut output_flips = [0_u64; 1024];
    let mut fixed_points = 0_usize;
    let mut two_cycles = 0_usize;

    for _ in 0..samples {
        let mut input = [0_u64; 16];
        for lane in &mut input {
            *lane = next_word(&mut seed);
        }
        let mut baseline_state = P1024V3::from_lanes(input);
        permute_rounds(&mut baseline_state, rounds);
        let baseline = *baseline_state.lanes();
        fixed_points += usize::from(baseline == input);
        let mut twice = P1024V3::from_lanes(baseline);
        permute_rounds(&mut twice, rounds);
        two_cycles += usize::from(twice.lanes() == &input);

        for input_bit in 0..1024 {
            let mut changed = input;
            changed[input_bit / 64] ^= 1_u64 << (input_bit % 64);
            let mut changed_state = P1024V3::from_lanes(changed);
            permute_rounds(&mut changed_state, rounds);
            let output = changed_state.lanes();
            let distance = hamming_distance(&baseline, output);
            minimum = minimum.min(distance);
            maximum = maximum.max(distance);
            total += u128::from(distance);
            derivatives += 1;
            for output_bit in 0..1024 {
                let mask = 1_u64 << (output_bit % 64);
                if (baseline[output_bit / 64] ^ output[output_bit / 64]) & mask != 0 {
                    output_flips[output_bit] += 1;
                }
            }
        }
    }

    let expected = derivatives as f64 / 2.0;
    let output_minimum = output_flips.iter().copied().min().unwrap_or(0);
    let output_maximum = output_flips.iter().copied().max().unwrap_or(0);
    println!("P1024-V3 empirical differential report");
    println!("rounds: {rounds}");
    println!("sampled states: {samples}");
    println!("single-bit derivatives: {derivatives}");
    println!(
        "Hamming distance: min={minimum}, max={maximum}, mean={:.3}",
        total as f64 / derivatives as f64
    );
    println!(
        "output-bit flips: min={output_minimum}, max={output_maximum}, ideal mean={expected:.1}"
    );
    println!("sampled fixed points: {fixed_points}");
    println!("sampled two-cycles: {two_cycles}");
    let mut zero = P1024V3::from_lanes([0; 16]);
    permute_rounds(&mut zero, rounds);
    println!("P_rounds(0):");
    for lane in zero.lanes() {
        println!("  {lane:016x}");
    }
    println!(
        "Важно: статистический отчёт не является доказательством криптографической стойкости."
    );
    ExitCode::SUCCESS
}
