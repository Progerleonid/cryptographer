use std::{env, process::ExitCode};

fn next_word(seed: &mut u64) -> u64 {
    *seed ^= *seed << 13;
    *seed ^= *seed >> 7;
    *seed ^= *seed << 17;
    *seed
}

fn layer(input: &[u64; 8], rotations: [u32; 4]) -> [u64; 8] {
    let mut output = [0_u64; 8];
    for index in 0..8 {
        output[index] = input[index]
            ^ input[(index + 1) % 8].rotate_left(rotations[0])
            ^ input[(index + 3) % 8].rotate_left(rotations[1])
            ^ input[(index + 5) % 8].rotate_left(rotations[2])
            ^ input[(index + 6) % 8].rotate_left(rotations[3]);
    }
    output
}

fn highest_bit(value: &[u64; 8]) -> Option<usize> {
    for lane in (0..8).rev() {
        if value[lane] != 0 {
            return Some(lane * 64 + 63 - value[lane].leading_zeros() as usize);
        }
    }
    None
}

fn binary_rank(rotations: [u32; 4]) -> usize {
    let mut basis: [Option<[u64; 8]>; 512] = [None; 512];
    let mut rank = 0;
    for input_bit in 0..512 {
        let mut input = [0_u64; 8];
        input[input_bit / 64] = 1_u64 << (input_bit % 64);
        let mut vector = layer(&input, rotations);
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

fn sampled_two_bit_minimum(rotations: [u32; 4], samples: usize, seed: &mut u64) -> u32 {
    let mut minimum = u32::MAX;
    for _ in 0..samples {
        let first = next_word(seed) as usize % 512;
        let mut second = next_word(seed) as usize % 512;
        if second == first {
            second = (second + 1) % 512;
        }
        let mut input = [0_u64; 8];
        input[first / 64] ^= 1_u64 << (first % 64);
        input[second / 64] ^= 1_u64 << (second % 64);
        let weight = layer(&input, rotations)
            .iter()
            .map(|word| word.count_ones())
            .sum();
        minimum = minimum.min(weight);
    }
    minimum
}

fn parse_candidates(arguments: &[String]) -> Result<usize, String> {
    let Some(index) = arguments
        .iter()
        .position(|argument| argument == "--candidates")
    else {
        return Ok(10_000);
    };
    let value = arguments
        .get(index + 1)
        .ok_or_else(|| "после --candidates требуется число".to_owned())?;
    value
        .parse::<usize>()
        .map_err(|_| format!("неверное число кандидатов: {value}"))
}

fn main() -> ExitCode {
    let arguments: Vec<String> = env::args().collect();
    if arguments.iter().any(|argument| argument == "--help") {
        println!(
            "Использование: cargo run --release --bin search_v3_rotations -- [--candidates 10000]"
        );
        return ExitCode::SUCCESS;
    }
    let candidates = match parse_candidates(&arguments) {
        Ok(value @ 1..=1_000_000) => value,
        Ok(value) => {
            eprintln!("--candidates должен быть в диапазоне 1..=1000000, получено {value}");
            return ExitCode::FAILURE;
        }
        Err(error) => {
            eprintln!("{error}");
            return ExitCode::FAILURE;
        }
    };
    let mut seed = 0x726f_7461_7469_6f6e_u64;
    let mut best = ([0_u32; 4], 0_usize, 0_u32);
    let mut recommended = Vec::new();
    for _ in 0..candidates {
        let candidate = [
            (next_word(&mut seed) % 63 + 1) as u32,
            (next_word(&mut seed) % 63 + 1) as u32,
            (next_word(&mut seed) % 63 + 1) as u32,
            (next_word(&mut seed) % 63 + 1) as u32,
        ];
        let mut distinct = candidate;
        distinct.sort_unstable();
        if distinct.windows(2).any(|pair| pair[0] == pair[1]) {
            continue;
        }
        let rank = binary_rank(candidate);
        if rank < best.1 {
            continue;
        }
        let minimum = sampled_two_bit_minimum(candidate, 4_096, &mut seed);
        if rank == 512 && minimum >= 8 && recommended.len() < 4 {
            recommended.push(candidate);
            println!("recommended[{}]={candidate:?}", recommended.len() - 1);
        }
        if (rank, minimum) > (best.1, best.2) {
            best = (candidate, rank, minimum);
            println!(
                "best rotations={:?}, binary_rank={}, sampled_two_bit_output_weight={}",
                best.0, best.1, best.2
            );
        }
    }
    println!(
        "Итог: rotations={:?}, rank={}, score={}",
        best.0, best.1, best.2
    );
    println!(
        "Найдено рекомендуемых full-rank наборов: {}",
        recommended.len()
    );
    println!("Поиск проверяет линейный слой, но не доказывает стойкость полной перестановки.");
    ExitCode::SUCCESS
}
