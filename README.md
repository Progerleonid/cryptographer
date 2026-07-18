# Obsidian Vault V3

Obsidian Vault — учебный консольный шифратор с полностью собственной
48-раундовой перестановкой P1024-V3, duplex/sponge, KDF, MAC, XOF,
SIV-подобным режимом и текстовым кодированием.

> Алгоритм экспериментальный. Статистические тесты, большой ключ и длинный тег
> не заменяют независимый профессиональный криптоанализ. Не используйте проект
> для защиты критичных данных.

Проект не использует AES, ChaCha, SHA, BLAKE, Argon2 или готовый AEAD.
`getrandom` получает случайные байты у ОС, а `zeroize` сокращает время жизни
секретов в памяти.

## V3

- Новые контейнеры имеют однозначный префикс `OV3-` и аутентифицированный
  8-байтовый бинарный заголовок.
- P1024-V3 — 1024-битная balanced Feistel-перестановка из 48 раундов.
- Раундовая функция разделена на четыре явных nonlinear и diffusion слоя.
- Каждый 512-битный diffusion layer имеет проверяемый бинарный ранг 512; наборы
  вращений сохранены вместе с воспроизводимым инструментом поиска.
- Все 1536 позиционных раундовых констант воспроизводимо выводятся публичной
  функцией `round_constant`.
- Sponge имеет rate 512 бит и capacity 512 бит; поля length-framed и имеют
  независимые domain identifiers.
- Из 64-байтового master key отдельно выводятся MAC, stream и commitment keys.
- Контейнер содержит 128-битный key commitment и 256-битный authentication tag.
- Tag входит в генерацию шифрующего потока. Повтор nonce для разных внутренних
  сообщений не повторяет поток при допущении стойкости собственных примитивов.
- В V3 всегда присутствует от 1 до 32 случайных padding bytes. Случая без
  случайного padding больше нет.
- Длина plaintext по-прежнему раскрывается с точностью до 32-байтового класса.
- V2 автоматически поддерживается для расшифрования. OV1 доступен через
  отдельную миграционную функцию.

Полная побайтовая спецификация находится в
[`V3_SPECIFICATION.md`](V3_SPECIFICATION.md).
Подробный математический разбор перестановки, duplex, KDF, MAC, XOF и полной
композиции находится в [`MATHEMATICS.md`](MATHEMATICS.md).

## Сборка и запуск

Требуется Rust 1.85 или новее.

```console
cargo build --release
cargo run --release --bin obsidian_vault
```

В интерактивном меню:

```text
1. Создать файл ключа
2. Зашифровать текст
3. Расшифровать текст
4. Выход
```

Сначала создайте 64-байтовый файл ключа. На Unix он создаётся с правами `0600`,
без перезаписи существующего файла и публикуется только после полной записи.
Храните отдельную резервную копию: потерянный ключ восстановить невозможно.

## Библиотечный API

```rust
use obsidian_vault::{ReplayGuard, VaultKey, decrypt_text_once, encrypt_text};

let key = VaultKey::generate()?;
let context = b"example-application:note:v3";
let encrypted = encrypt_text("Привет", &key, context)?;
assert!(encrypted.starts_with("OV3-"));

let mut replay_guard = ReplayGuard::new(10_000);
let decrypted = decrypt_text_once(&encrypted, &key, context, &mut replay_guard)?;
assert_eq!(decrypted.as_str(), "Привет");
# Ok::<(), obsidian_vault::VaultError>(())
```

Пустой context отклоняется. Используйте уникальный канонический context для
каждого приложения и типа записи. Stateless `decrypt_*` проверяет целостность,
но не freshness. `decrypt_*_once` хранит bounded replay window только в памяти;
между перезапусками replay state должен сохранять вызывающий код.

Максимальный plaintext — 16 MiB, context — 4096 байтов.

## Формат V3

```text
"OV3-" || Encode64(
    header[8]
    || key_commitment[16]
    || nonce[24]
    || synthetic_tag[32]
    || encrypted_inner[n * 32]
)
```

Внутренний блок:

```text
version[1] || flags[1] || reserved[2]
|| plaintext_length_le[4] || plaintext || random_padding[1..32]
```

## Анализ собственной перестановки

Полная empirical avalanche-проверка всех 1024 single-bit derivatives:

```console
cargo run --release --bin analyze_v3 -- --rounds 48 --samples 16
```

Сравнение reduced-round поведения:

```console
cargo run --release --bin analyze_v3 -- --rounds 8 --samples 16
cargo run --release --bin analyze_v3 -- --rounds 16 --samples 16
cargo run --release --bin analyze_v3 -- --rounds 32 --samples 16
cargo run --release --bin analyze_v3 -- --rounds 48 --samples 16
```

Поиск полнопорядковых наборов вращений для линейного слоя:

```console
cargo run --release --bin search_v3_rotations -- --candidates 10000
```

Эти программы ищут грубые дефекты и регрессии. Они не доказывают PRP/PRF,
IND-CCA, misuse resistance или отсутствие дифференциальных, линейных,
интегральных, rotational и алгебраических атак.

## Проверки

```console
cargo fmt --all -- --check
cargo test --all-targets --all-features
cargo clippy --all-targets --all-features -- -D warnings
cargo build --release --all-targets
```

Тесты включают фиксированные векторы V2/P1024-V3, обратимость Feistel,
диффузию всех 1024 входных битов, повреждение всех областей V3, wrong
key/context, nonce reuse, обязательный random padding, replay guard, границы
размеров, key-файлы и миграционные OV1/V2-векторы.
