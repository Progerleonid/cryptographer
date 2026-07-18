use core::fmt;

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum VaultError {
    InvalidData,
    UnsupportedVersion,
    InputTooLarge,
    RandomFailure,
    Io,
    KeyFileExists,
    InvalidKeyFile,
    InsecureKeyFile,
    InvalidContext,
    ReplayDetected,
    ReplayWindowFull,
}

impl fmt::Debug for VaultError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidData => "InvalidData",
            Self::UnsupportedVersion => "UnsupportedVersion",
            Self::InputTooLarge => "InputTooLarge",
            Self::RandomFailure => "RandomFailure",
            Self::Io => "Io",
            Self::KeyFileExists => "KeyFileExists",
            Self::InvalidKeyFile => "InvalidKeyFile",
            Self::InsecureKeyFile => "InsecureKeyFile",
            Self::InvalidContext => "InvalidContext",
            Self::ReplayDetected => "ReplayDetected",
            Self::ReplayWindowFull => "ReplayWindowFull",
        })
    }
}

impl fmt::Display for VaultError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::UnsupportedVersion => "Ошибка: версия контейнера не поддерживается.",
            Self::InputTooLarge => "Ошибка: текст превышает допустимый размер.",
            Self::RandomFailure => "Ошибка: не удалось получить случайные данные.",
            Self::Io => "Ошибка ввода-вывода.",
            Self::KeyFileExists => "Ошибка: файл ключа уже существует; перезапись запрещена.",
            Self::InvalidKeyFile => "Ошибка: неверный формат или тип файла ключа.",
            Self::InsecureKeyFile => {
                "Ошибка: файл ключа доступен другим пользователям; требуются права 0600."
            }
            Self::InvalidContext => "Ошибка: context не должен быть пустым.",
            Self::ReplayDetected => "Ошибка: контейнер уже был принят ранее.",
            Self::ReplayWindowFull => "Ошибка: хранилище replay-защиты заполнено.",
            Self::InvalidData => "Ошибка: неверный ключ или повреждённые данные.",
        })
    }
}

impl std::error::Error for VaultError {}
