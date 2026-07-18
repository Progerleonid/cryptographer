use std::{collections::HashSet, time::Instant};

#[cfg(unix)]
use std::{
    fs,
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

#[cfg(unix)]
use obsidian_vault::keyfile::{load_key_file, load_legacy_key_file};
use obsidian_vault::{
    ReplayGuard, V3_MAX_TEXT_SIZE, VaultError, VaultKey, decrypt_bytes, decrypt_bytes_once,
    encrypt_bytes,
};

const CONTEXT: &[u8] = b"security-audit:v1";
const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz123456789-_~";
#[cfg(unix)]
static TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

#[cfg(unix)]
struct TemporaryDirectory(PathBuf);

#[cfg(unix)]
impl TemporaryDirectory {
    fn new(label: &str) -> Self {
        let counter = TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "obsidian-security-audit-{label}-{}-{counter}",
            std::process::id()
        ));
        fs::create_dir(&path).expect("temporary directory creation");
        Self(path)
    }

    fn join(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }
}

#[cfg(unix)]
impl Drop for TemporaryDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn alphabet_value(byte: u8) -> u8 {
    ALPHABET
        .iter()
        .position(|candidate| *candidate == byte)
        .expect("valid audit encoding") as u8
}

fn decode_v3(input: &str) -> Vec<u8> {
    let bytes = input.strip_prefix("OV3-").expect("V3 prefix").as_bytes();
    let mut output = Vec::with_capacity(bytes.len() * 3 / 4);
    let mut index = 0;
    while index + 4 <= bytes.len() {
        let a = alphabet_value(bytes[index]);
        let b = alphabet_value(bytes[index + 1]);
        let c = alphabet_value(bytes[index + 2]);
        let d = alphabet_value(bytes[index + 3]);
        output.push((a << 2) | (b >> 4));
        output.push((b << 4) | (c >> 2));
        output.push((c << 6) | d);
        index += 4;
    }
    if bytes.len() - index == 2 {
        let a = alphabet_value(bytes[index]);
        let b = alphabet_value(bytes[index + 1]);
        output.push((a << 2) | (b >> 4));
    } else if bytes.len() - index == 3 {
        let a = alphabet_value(bytes[index]);
        let b = alphabet_value(bytes[index + 1]);
        let c = alphabet_value(bytes[index + 2]);
        output.push((a << 2) | (b >> 4));
        output.push((b << 4) | (c >> 2));
    }
    output
}

fn encode_v3(data: &[u8]) -> String {
    let mut output = String::with_capacity(4 + data.len() * 4_usize.div_ceil(3));
    output.push_str("OV3-");
    let mut chunks = data.chunks_exact(3);
    for chunk in &mut chunks {
        output.push(char::from(ALPHABET[usize::from(chunk[0] >> 2)]));
        output.push(char::from(
            ALPHABET[usize::from(((chunk[0] & 3) << 4) | (chunk[1] >> 4))],
        ));
        output.push(char::from(
            ALPHABET[usize::from(((chunk[1] & 15) << 2) | (chunk[2] >> 6))],
        ));
        output.push(char::from(ALPHABET[usize::from(chunk[2] & 63)]));
    }
    match chunks.remainder() {
        [a] => {
            output.push(char::from(ALPHABET[usize::from(a >> 2)]));
            output.push(char::from(ALPHABET[usize::from((a & 3) << 4)]));
        }
        [a, b] => {
            output.push(char::from(ALPHABET[usize::from(a >> 2)]));
            output.push(char::from(ALPHABET[usize::from(((a & 3) << 4) | (b >> 4))]));
            output.push(char::from(ALPHABET[usize::from((b & 15) << 2)]));
        }
        _ => {}
    }
    output
}

#[test]
fn proto_01_replay_guard_rejects_the_second_delivery() {
    let key = VaultKey::from_bytes([0x31; 64]);
    let encoded = encrypt_bytes(b"execute-once", &key, CONTEXT).expect("encryption");
    let mut replay_guard = ReplayGuard::new(16);

    let first =
        decrypt_bytes_once(&encoded, &key, CONTEXT, &mut replay_guard).expect("first delivery");
    let second = decrypt_bytes_once(&encoded, &key, CONTEXT, &mut replay_guard);

    assert_eq!(first.as_slice(), b"execute-once");
    assert!(matches!(second, Err(VaultError::ReplayDetected)));
}

#[test]
fn api_01_empty_context_is_rejected() {
    let key = VaultKey::from_bytes([0x41; 64]);
    assert!(matches!(
        encrypt_bytes(b"domain-a record", &key, b""),
        Err(VaultError::InvalidContext)
    ));
    assert!(matches!(
        decrypt_bytes("", &key, b""),
        Err(VaultError::InvalidContext)
    ));
}

#[test]
fn crypto_01_every_binary_byte_is_authenticated_for_a_small_container() {
    let key = VaultKey::from_bytes([0x51; 64]);
    let encoded = encrypt_bytes(b"tamper probe", &key, CONTEXT).expect("encryption");
    let binary = decode_v3(&encoded);

    for index in 0..binary.len() {
        let mut changed = binary.clone();
        changed[index] ^= 1;
        assert!(matches!(
            decrypt_bytes(&encode_v3(&changed), &key, CONTEXT),
            Err(VaultError::InvalidData)
        ));
    }
}

#[test]
fn crypto_01_sampled_os_nonces_do_not_repeat() {
    let key = VaultKey::from_bytes([0x61; 64]);
    let mut nonces = HashSet::new();

    for _ in 0..1_024 {
        let encoded = encrypt_bytes(b"nonce probe", &key, CONTEXT).expect("encryption");
        let binary = decode_v3(&encoded);
        assert!(
            nonces.insert(binary[..24].to_vec()),
            "sampled nonce repeated"
        );
    }
}

#[test]
fn format_v3_has_explicit_authenticated_version_header() {
    let key = VaultKey::from_bytes([0x71; 64]);
    let mut prefixes = HashSet::new();

    for _ in 0..32 {
        let encoded = encrypt_bytes(b"format probe", &key, CONTEXT).expect("encryption");
        assert!(encoded.starts_with("OV3-"));
        let binary = decode_v3(&encoded);
        assert_eq!(&binary[..8], b"OBSV3\0\x01\0");
        prefixes.insert(binary[24..32].to_vec());
    }

    assert_eq!(
        prefixes.len(),
        32,
        "the sampled external prefixes were not random"
    );
}

#[cfg(unix)]
#[test]
fn keyfile_01_direct_symlink_is_rejected() {
    use std::os::unix::fs::{PermissionsExt, symlink};

    let directory = TemporaryDirectory::new("direct-symlink");
    let target = directory.join("target.key");
    let link = directory.join("link.key");
    fs::write(&target, [0x81; 64]).expect("target write");
    fs::set_permissions(&target, fs::Permissions::from_mode(0o600)).expect("target permissions");
    symlink(&target, &link).expect("symlink creation");

    assert!(matches!(
        load_key_file(&link),
        Err(VaultError::InvalidKeyFile)
    ));
}

#[cfg(unix)]
#[test]
fn memory_01_legacy_partial_utf8_error_is_rejected() {
    use std::os::unix::fs::PermissionsExt;

    let directory = TemporaryDirectory::new("legacy-read-error");
    let path = directory.join("legacy.key");
    let mut contents = vec![b'A'; 64];
    contents.push(0xff);
    fs::write(&path, contents).expect("legacy fixture write");
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("fixture permissions");

    assert!(matches!(
        load_legacy_key_file(&path),
        Err(VaultError::InvalidKeyFile)
    ));
}

// These ignored tests exercise adversarial filesystem/resource conditions. They are intentionally
// excluded from the ordinary suite because one is probabilistic and the others deliberately
// consume resources or crash a child process.

#[cfg(unix)]
#[test]
#[ignore = "probabilistic TOCTOU regression"]
fn keyfile_01_path_swap_never_follows_the_symlink() {
    use std::{
        os::unix::fs::{PermissionsExt, symlink},
        sync::{
            Arc,
            atomic::{AtomicBool, Ordering as AtomicOrdering},
        },
        thread,
    };

    let directory = TemporaryDirectory::new("path-swap");
    let legitimate = directory.join("legitimate.key");
    let attacker = directory.join("attacker.key");
    let candidate = directory.join("candidate.key");
    fs::write(&legitimate, [0x91; 64]).expect("legitimate key write");
    fs::write(&attacker, [0xa1; 64]).expect("attacker key write");
    for path in [&legitimate, &attacker] {
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).expect("key permissions");
    }
    fs::hard_link(&legitimate, &candidate).expect("initial candidate");

    let attacker_ciphertext = encrypt_bytes(
        b"attacker-selected key was loaded",
        &VaultKey::from_bytes([0xa1; 64]),
        CONTEXT,
    )
    .expect("attacker fixture encryption");
    let stop = Arc::new(AtomicBool::new(false));
    let worker_stop = Arc::clone(&stop);
    let worker_candidate = candidate.clone();
    let worker_legitimate = legitimate.clone();
    let worker_attacker = attacker.clone();
    let worker = thread::spawn(move || {
        while !worker_stop.load(AtomicOrdering::Relaxed) {
            let _ = fs::remove_file(&worker_candidate);
            let _ = fs::hard_link(&worker_legitimate, &worker_candidate);
            thread::yield_now();
            let _ = fs::remove_file(&worker_candidate);
            let _ = symlink(&worker_attacker, &worker_candidate);
            thread::yield_now();
        }
    });

    let deadline = Instant::now() + std::time::Duration::from_secs(10);
    let mut bypassed = false;
    while Instant::now() < deadline {
        if let Ok(loaded) = load_key_file(&candidate)
            && decrypt_bytes(&attacker_ciphertext, &loaded, CONTEXT).is_ok()
        {
            bypassed = true;
            break;
        }
    }
    stop.store(true, AtomicOrdering::Relaxed);
    worker.join().expect("path swap worker");
    assert!(!bypassed, "path swap loaded the attacker-selected key");
}

#[cfg(unix)]
#[test]
#[ignore = "deliberately limits and crashes a child process"]
fn keyfile_02_interrupted_write_does_not_publish_the_target() {
    use std::{
        io::Write,
        process::{Command, Stdio},
    };

    fn run_cli(binary: &Path, input: &str, file_size_limit_zero: bool) -> std::process::Output {
        let mut command = if file_size_limit_zero {
            let mut command = Command::new("/bin/sh");
            command.args(["-c", "ulimit -f 0; exec \"$1\"", "audit-sh"]);
            command.arg(binary);
            command
        } else {
            Command::new(binary)
        };
        let mut child = command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("CLI spawn");
        child
            .stdin
            .take()
            .expect("child stdin")
            .write_all(input.as_bytes())
            .expect("CLI input");
        child.wait_with_output().expect("CLI completion")
    }

    let directory = TemporaryDirectory::new("partial-write");
    let path = directory.join("created.key");
    let binary = Path::new(env!("CARGO_BIN_EXE_obsidian_vault"));
    let input = format!("1\n{}\n4\n", path.display());

    let first = run_cli(binary, &input, true);
    assert!(
        !first.status.success(),
        "the write-limited child unexpectedly succeeded"
    );
    assert!(!path.exists(), "an incomplete target was published");

    let retry = run_cli(binary, &input, false);
    let stdout = String::from_utf8_lossy(&retry.stdout);
    assert!(
        retry.status.success() && stdout.contains("Файл ключа создан"),
        "retry did not create a complete key file: {stdout}"
    );
    assert_eq!(fs::metadata(&path).expect("created key metadata").len(), 64);
}

#[test]
#[ignore = "allocates and authenticates a maximum-size unauthenticated container"]
fn dos_01_maximum_syntactically_valid_input_cost() {
    let key = VaultKey::from_bytes([0xb1; 64]);
    let encoded = format!("OV3-{}", "A".repeat(V3_MAX_TEXT_SIZE - 4));
    let started = Instant::now();
    let result = decrypt_bytes(&encoded, &key, CONTEXT);
    let elapsed = started.elapsed();

    eprintln!(
        "DOS-01: processed {} unauthenticated text bytes in {:.3?}",
        encoded.len(),
        elapsed
    );
    assert!(matches!(result, Err(VaultError::InvalidData)));
}
