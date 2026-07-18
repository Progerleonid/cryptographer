use std::{
    fs::{self, OpenOptions},
    io::Write,
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
};

use obsidian_vault::{
    VaultError,
    keyfile::{create_key_file, load_key_file},
};
#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

static COUNTER: AtomicU64 = AtomicU64::new(0);

struct TemporaryFile(PathBuf);

impl TemporaryFile {
    fn new(label: &str) -> Self {
        let id = COUNTER.fetch_add(1, Ordering::Relaxed);
        Self(std::env::temp_dir().join(format!("obsidian-v2-{label}-{}-{id}", std::process::id())))
    }
}

impl Drop for TemporaryFile {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}

#[test]
fn key_file_is_created_once_and_loads() {
    let path = TemporaryFile::new("create");
    create_key_file(&path.0).expect("key creation failed");
    assert_eq!(fs::metadata(&path.0).expect("metadata").len(), 64);
    let _key = load_key_file(&path.0).expect("key load failed");
    assert!(matches!(
        create_key_file(&path.0),
        Err(VaultError::KeyFileExists)
    ));
    #[cfg(unix)]
    assert_eq!(
        fs::metadata(&path.0)
            .expect("metadata")
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
}

#[test]
fn wrong_size_and_insecure_permissions_are_rejected() {
    let path = TemporaryFile::new("invalid");
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        options.mode(0o600);
    }
    options
        .open(&path.0)
        .and_then(|mut file| file.write_all(&[1; 63]))
        .expect("fixture creation");
    assert!(matches!(
        load_key_file(&path.0),
        Err(VaultError::InvalidKeyFile)
    ));

    #[cfg(unix)]
    {
        fs::write(&path.0, [2; 64]).expect("fixture rewrite");
        fs::set_permissions(&path.0, fs::Permissions::from_mode(0o644)).expect("permission change");
        assert!(matches!(
            load_key_file(&path.0),
            Err(VaultError::InsecureKeyFile)
        ));
    }
}
