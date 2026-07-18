use std::{
    ffi::OsString,
    fs::{self, File, OpenOptions, symlink_metadata},
    io::{Read, Write},
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

#[cfg(unix)]
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use zeroize::Zeroize;

use crate::{VaultError, VaultKey, v2::V2_KEY_SIZE};

static TEMPORARY_FILE_COUNTER: AtomicU64 = AtomicU64::new(0);

struct TemporaryKeyFile {
    path: PathBuf,
    file: File,
}

impl Drop for TemporaryKeyFile {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

fn create_temporary_key_file(target: &Path) -> Result<TemporaryKeyFile, VaultError> {
    let file_name = target.file_name().ok_or(VaultError::Io)?;
    for _ in 0..128 {
        let counter = TEMPORARY_FILE_COUNTER.fetch_add(1, Ordering::Relaxed);
        let mut temporary_name = OsString::from(".");
        temporary_name.push(file_name);
        temporary_name.push(format!(".tmp-{}-{counter}", std::process::id()));
        let temporary_path = target.with_file_name(temporary_name);

        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        options.mode(0o600);
        match options.open(&temporary_path) {
            Ok(file) => {
                return Ok(TemporaryKeyFile {
                    path: temporary_path,
                    file,
                });
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(_) => return Err(VaultError::Io),
        }
    }
    Err(VaultError::Io)
}

fn open_key_file(path: &Path) -> Result<File, VaultError> {
    #[cfg(unix)]
    {
        let mut options = OpenOptions::new();
        options.read(true).custom_flags(libc::O_NOFOLLOW);
        options.open(path).map_err(|error| {
            if error.raw_os_error() == Some(libc::ELOOP) {
                VaultError::InvalidKeyFile
            } else {
                VaultError::Io
            }
        })
    }
    #[cfg(not(unix))]
    {
        File::open(path).map_err(|_| VaultError::Io)
    }
}

#[cfg(unix)]
fn same_file(left: &fs::Metadata, right: &fs::Metadata) -> bool {
    left.dev() == right.dev() && left.ino() == right.ino()
}

pub fn create_key_file(path: impl AsRef<Path>) -> Result<(), VaultError> {
    let path = path.as_ref();
    let key = VaultKey::generate()?;
    let mut temporary = create_temporary_key_file(path)?;
    temporary
        .file
        .write_all(key.as_bytes())
        .map_err(|_| VaultError::Io)?;
    temporary.file.sync_all().map_err(|_| VaultError::Io)?;
    fs::hard_link(&temporary.path, path).map_err(|error| {
        if error.kind() == std::io::ErrorKind::AlreadyExists {
            VaultError::KeyFileExists
        } else {
            VaultError::Io
        }
    })?;
    Ok(())
}

pub fn load_key_file(path: impl AsRef<Path>) -> Result<VaultKey, VaultError> {
    let path = path.as_ref();
    let link_metadata = symlink_metadata(path).map_err(|_| VaultError::Io)?;
    if link_metadata.file_type().is_symlink() || !link_metadata.is_file() {
        return Err(VaultError::InvalidKeyFile);
    }
    #[cfg(unix)]
    if link_metadata.permissions().mode() & 0o077 != 0 {
        return Err(VaultError::InsecureKeyFile);
    }
    if link_metadata.len() != V2_KEY_SIZE as u64 {
        return Err(VaultError::InvalidKeyFile);
    }

    let mut file = open_key_file(path)?;
    let opened_metadata = file.metadata().map_err(|_| VaultError::Io)?;
    #[cfg(unix)]
    if !same_file(&link_metadata, &opened_metadata) {
        return Err(VaultError::InvalidKeyFile);
    }
    if !opened_metadata.is_file() || opened_metadata.len() != V2_KEY_SIZE as u64 {
        return Err(VaultError::InvalidKeyFile);
    }
    #[cfg(unix)]
    if opened_metadata.permissions().mode() & 0o077 != 0 {
        return Err(VaultError::InsecureKeyFile);
    }

    let mut bytes = [0_u8; V2_KEY_SIZE];
    if let Err(error) = file.read_exact(&mut bytes) {
        bytes.zeroize();
        return Err(if error.kind() == std::io::ErrorKind::UnexpectedEof {
            VaultError::InvalidKeyFile
        } else {
            VaultError::Io
        });
    }
    Ok(VaultKey::from_bytes(bytes))
}

pub fn load_legacy_key_file(path: impl AsRef<Path>) -> Result<String, VaultError> {
    let path = path.as_ref();
    let link_metadata = symlink_metadata(path).map_err(|_| VaultError::Io)?;
    if link_metadata.file_type().is_symlink()
        || !link_metadata.is_file()
        || link_metadata.len() > 130
    {
        return Err(VaultError::InvalidKeyFile);
    }
    #[cfg(unix)]
    if link_metadata.permissions().mode() & 0o077 != 0 {
        return Err(VaultError::InsecureKeyFile);
    }
    let file = open_key_file(path)?;
    let opened_metadata = file.metadata().map_err(|_| VaultError::Io)?;
    #[cfg(unix)]
    if !same_file(&link_metadata, &opened_metadata) {
        return Err(VaultError::InvalidKeyFile);
    }
    if !opened_metadata.is_file() || opened_metadata.len() > 130 {
        return Err(VaultError::InvalidKeyFile);
    }
    #[cfg(unix)]
    if opened_metadata.permissions().mode() & 0o077 != 0 {
        return Err(VaultError::InsecureKeyFile);
    }
    let mut value = String::new();
    file.take(131)
        .read_to_string(&mut value)
        .map_err(|_| VaultError::InvalidKeyFile)?;
    while value.ends_with('\n') || value.ends_with('\r') {
        value.pop();
    }
    if value.len() != 128 {
        value.zeroize();
        return Err(VaultError::InvalidKeyFile);
    }
    Ok(value)
}
