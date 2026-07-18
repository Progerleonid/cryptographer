use std::io::{self, Write};

use obsidian_vault::{
    VaultError, decrypt_ov1_text, decrypt_text, encrypt_text, is_v3_container,
    keyfile::{create_key_file, load_key_file, load_legacy_key_file},
};
use zeroize::Zeroize;

const CLI_CONTEXT_V3: &[u8] = b"obsidian-vault-cli:text:v3";
const CLI_CONTEXT_V2: &[u8] = b"obsidian-vault-cli:text:v2";
const MENU: &str = "================================\nOBSIDIAN VAULT V3\n=================\n\n1. Создать файл ключа\n2. Зашифровать текст\n3. Расшифровать текст\n4. Выход\nВыберите действие: ";

fn read_line(prompt: &str) -> Result<Option<String>, VaultError> {
    print!("{prompt}");
    io::stdout().flush().map_err(|_| VaultError::Io)?;
    let mut line = String::new();
    let count = io::stdin()
        .read_line(&mut line)
        .map_err(|_| VaultError::Io)?;
    if count == 0 {
        return Ok(None);
    }
    if line.ends_with('\n') {
        line.pop();
        if line.ends_with('\r') {
            line.pop();
        }
    }
    Ok(Some(line))
}

fn read_multiline(prompt: &str) -> Result<Option<String>, VaultError> {
    println!("{prompt}");
    println!("Для завершения введите точку на отдельной строке:");
    io::stdout().flush().map_err(|_| VaultError::Io)?;

    let mut text = String::new();
    loop {
        let mut line = String::new();
        let count = io::stdin()
            .read_line(&mut line)
            .map_err(|_| VaultError::Io)?;
        if count == 0 {
            return if text.is_empty() {
                Ok(None)
            } else {
                Ok(Some(text))
            };
        }

        let line_without_ending = line.trim_end_matches(['\r', '\n']);
        if line_without_ending == "." {
            break;
        }
        if !text.is_empty() {
            text.push('\n');
        }
        text.push_str(line_without_ending);
    }
    Ok(Some(text))
}

fn create_key_action() -> Result<(), VaultError> {
    let Some(path) = read_line("Путь для нового файла ключа: ")? else {
        return Ok(());
    };
    create_key_file(path.trim())?;
    println!("\nФайл ключа создан. Храните резервную копию отдельно.\n");
    Ok(())
}

fn encrypt_action() -> Result<(), VaultError> {
    let Some(mut text) = read_multiline("Введите текст")? else {
        return Ok(());
    };
    let Some(path) = read_line("Путь к файлу ключа: ")? else {
        text.zeroize();
        return Ok(());
    };
    let key = load_key_file(path.trim())?;
    let encrypted = encrypt_text(&text, &key, CLI_CONTEXT_V3);
    text.zeroize();
    println!("\nШИФРОТЕКСТ:\n{}\n", encrypted?);
    Ok(())
}

fn decrypt_action() -> Result<(), VaultError> {
    let Some(container) = read_line("Введите шифротекст: ")? else {
        return Ok(());
    };
    let Some(path) = read_line("Путь к файлу ключа: ")? else {
        return Ok(());
    };
    if container.starts_with("OV1-") {
        let mut legacy_key = load_legacy_key_file(path.trim())?;
        let result = decrypt_ov1_text(&container, &legacy_key);
        legacy_key.zeroize();
        let plaintext = result?;
        println!(
            "\nРАСШИФРОВАННЫЙ ТЕКСТ (OV1, только миграция):\n{}\n",
            plaintext.as_str()
        );
    } else {
        let key = load_key_file(path.trim())?;
        let context = if is_v3_container(&container) {
            CLI_CONTEXT_V3
        } else {
            CLI_CONTEXT_V2
        };
        let plaintext = decrypt_text(&container, &key, context)?;
        println!("\nРАСШИФРОВАННЫЙ ТЕКСТ:\n{}\n", plaintext.as_str());
    }
    Ok(())
}

fn main() {
    loop {
        let selection = match read_line(MENU) {
            Ok(Some(value)) => value,
            Ok(None) => break,
            Err(error) => {
                eprintln!("{error}");
                break;
            }
        };
        let result = match selection.trim() {
            "1" => create_key_action(),
            "2" => encrypt_action(),
            "3" => decrypt_action(),
            "4" => break,
            _ => {
                println!("Ошибка: выберите 1, 2, 3 или 4.\n");
                continue;
            }
        };
        if let Err(error) = result {
            println!("{error}\n");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::MENU;

    #[test]
    fn menu_has_v3_choices() {
        assert!(MENU.contains("OBSIDIAN VAULT V3"));
        assert!(MENU.contains("Создать файл ключа"));
        assert!(MENU.contains("Зашифровать текст"));
        assert!(MENU.contains("Расшифровать текст"));
        assert!(MENU.contains("4. Выход"));
    }
}
