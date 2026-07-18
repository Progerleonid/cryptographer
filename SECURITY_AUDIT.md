# Защитный аудит Obsidian Vault V2

> Исторический отчёт относится к V2 до появления V3. Новое шифрование теперь
> создаёт версионированные контейнеры V3; V2 оставлен только для совместимого
> чтения. Спецификация и актуальные ограничения V3 находятся в
> `V3_SPECIFICATION.md` и `README.md`. V3 также остаётся экспериментальной
> собственной конструкцией без независимого криптоанализа.

Дата первоначального аудита и перепроверки: 2026-07-17
Объём: этапы 1–4 исходного задания и последующая перепроверка каждой находки минимальными tests/локальными PoC.
После аудита исправлены KEYFILE-01, KEYFILE-02 и API-01, добавлен bounded stateful API для PROTO-01 и убран линейный lookup из DOS-01. Криптографическая конструкция и формат контейнера не изменялись.

## Краткий вывод

В ходе аудита не получено оснований считать алгоритм или систему безопасными. V2 построен целиком на собственной P1024‑V2-перестановке, sponge, KDF/MAC/XOF и SIV-подобной композиции. Код аккуратно ограничивает размеры, использует ОС-источник случайности, разделяет домены и ключевые назначения, а также не возвращает plaintext до успешной проверки тега. Однако конфиденциальность и неforgeability всей схемы зависят от непроверенной стойкости новой перестановки и нестандартной композиции. Функциональные тесты, fixed vectors, обратимость и avalanche-тест этого не подтверждают.

После попыток опровержения подтверждены: отсутствие replay-защиты; реальное TOCTOU-окно между `symlink_metadata` и `open`; сохранение неполного key-файла после прерванной записи; приём пустого `context`. При этом два результата были ослаблены: максимальный 22 369 739-байтовый unauthenticated V2 input занял 608.957 ms в release, поэтому DOS-01 понижен с Medium до Low; пустой context сам по себе является допустимым для криптографического API поведением, поэтому API-01 понижен с Low до Informational и остаётся проблемой только при нарушении application-level domain policy. FORMAT-01 не является текущей downgrade-уязвимостью, а MEMORY-01 в основном описывает явно документированные границы zeroization.

После добавления сначала падающих regression tests KEYFILE-01 закрыт на Unix через `O_NOFOLLOW` и сравнение `dev/inode` до/после открытия, включая legacy loader. KEYFILE-02 закрыт публикацией только полностью записанного и синхронизированного временного файла через atomic no-clobber hard link. Regression tests после исправления проходят; авария до публикации может оставить скрытый temporary file, но не целевой key-файл.

Наиболее серьёзная находка CRYPTO-01 не подтверждена как уязвимость и не опровергнута: побайтовое изменение каждого байта малого бинарного контейнера отклоняется, 1 024 sampled nonce не повторились, а существующие inverse/avalanche/vector/nonce-reuse tests проходят. Эти проверки исключают несколько простых реализационных ошибок, но не доказывают PRP/PRF, MAC-forgery, CCA или misuse-resistant стойкость собственной конструкции. Critical-находок нет.

Автоматические проверки форматирования, компиляции, Clippy и 31 обычный тест прошли; 3 audit PoC, помеченные `ignored`, были запущены отдельно и прошли. Дубликатов зависимостей нет. `cargo audit` не завершился из-за недоступной для записи advisory-базы и запрета сети. `unsafe` в основной реализации и добавленных тестах не используется; nightly не установлен, поэтому Miri не запускался.

## Таблица находок

| ID | Severity | Confidence | Статус после перепроверки | Файл и строки | Категория | Краткое описание |
|---|---|---|---|---|---|---|
| CRYPTO-01 | High | Speculative | Не подтверждена и не опровергнута; assurance gap | `src/v2_permutation.rs:3-111`; `src/v2_sponge.rs:19-137`; `src/v2.rs:142-209`; legacy: `src/permutation.rs:77-139`, `src/sponge.rs:21-79`, `src/vault.rs:40-135` | Криптографическая конструкция | Простые tamper/nonce/inverse/avalanche проверки проходят, но не подтверждают PRP/PRF, collision, differential, linear, related-key, CCA и misuse-resistant стойкость. |
| PROTO-01 | Medium | Confirmed | Исправлена в `decrypt_*_once`; stateless API не даёт freshness | `src/v2.rs`; `tests/security_audit.rs`, `proto_01_replay_guard_rejects_the_second_delivery` | Replay / API | Bounded `ReplayGuard` отклоняет вторую доставку после успешной аутентификации; persistence остаётся за caller. |
| DOS-01 | Low (понижена с Medium) | Confirmed | Линейный alphabet lookup исправлен; operational risk остался | `src/v2_encoding.rs`; `tests/security_audit.rs`, `dos_01_maximum_syntactically_valid_input_cost` | DoS по CPU/памяти | Decoder использует 256-byte direct lookup. Полная SIV-проверка большого ввода по-прежнему требует deployment limits. |
| KEYFILE-01 | Low | Confirmed | Исправлена; regression PASS на Unix | `src/keyfile.rs`; `tests/security_audit.rs`, `keyfile_01_path_swap_never_follows_the_symlink` | TOCTOU / файловый ввод-вывод | До исправления path swap загружал второй key-файл; теперь symlink запрещён при самом `open`, а identity открытого файла сверяется с проверенной metadata. |
| KEYFILE-02 | Low | Confirmed | Исправлена; regression PASS | `src/keyfile.rs`; `tests/security_audit.rs`, `keyfile_02_interrupted_write_does_not_publish_the_target` | Надёжность / частичная запись | До исправления аварийная запись оставляла короткий target; теперь target публикуется только после полной записи и `sync_all`. |
| API-01 | Informational (понижена с Low) | Confirmed | Исправлена; regression PASS | `src/v2.rs`; `tests/security_audit.rs`, `api_01_empty_context_is_rejected` | Domain separation / API contract | Public encrypt/decrypt API отклоняет пустой context с `InvalidContext`. |
| FORMAT-01 | Informational | Confirmed | Не текущая уязвимость; design debt | `src/v2.rs:25,96-131,157-161,173-209`; `src/main.rs:62-75`; `tests/security_audit.rs:163-179` | Версионирование / downgrade | У V2 нет fixed external header; 32 sampled prefixes различались. CLI/API сейчас однозначно выбирают V2/OV1, прямой downgrade не воспроизведён. |
| MEMORY-01 | Informational | High | Error path подтверждён; извлечение остатка не подтверждено | `src/v2.rs:194-228`; `src/vault.rs:108-135`; `src/keyfile.rs:54-63,76-88`; `tests/security_audit.rs:199-215` | Жизненный цикл секретов | Legacy UTF-8 read error воспроизводится до явного `zeroize`; возможность извлечь остаток после обычного `String` drop не доказана. Общие границы zeroize документированы. |

## Матрица попыток опровержения

| ID | Контраргумент / попытка опровержения | Минимальный тест или PoC | Результат |
|---|---|---|---|
| CRYPTO-01 | Возможно, имеющиеся inverse/avalanche/vector tests и полная аутентификация уже исключают проблему | `crypto_01_every_binary_byte_is_authenticated_for_a_small_container`, `crypto_01_sampled_os_nonces_do_not_repeat`, существующие unit tests | Все прошли; простая malleability и sampled nonce collision не найдены. Стойкость примитива не доказана, поэтому High остаётся только как Speculative assurance risk. |
| PROTO-01 | Возможно, nonce/tag автоматически делают повтор недействительным | Исходный PoC; затем `proto_01_replay_guard_rejects_the_second_delivery` | Stateless decrypt подтвердил проблему. После исправления `decrypt_*_once` возвращает `ReplayDetected` при второй доставке. |
| DOS-01 | Возможно, лимит достаточно мал и обработка практически дешева | `dos_01_maximum_syntactically_valid_input_cost`, release | 22 369 739 bytes → `InvalidData` за 608.957 ms. Предаутентификационная работа есть, но Medium для локального CLI завышена. |
| KEYFILE-01 | Первая `symlink_metadata` может полностью закрывать symlink attack | Исходный PoC; затем `keyfile_01_path_swap_never_follows_the_symlink` | До исправления конкурентная подмена загрузила второй файл. После `O_NOFOLLOW` и проверки identity 10-секундный regression не получил атакующий ключ. |
| KEYFILE-02 | `write_all`/Drop/повтор могли автоматически убрать или восстановить target | Исходный PoC; затем `keyfile_02_interrupted_write_does_not_publish_the_target` | До исправления child с `ulimit -f 0` оставил короткий target. После исправления target отсутствует, а обычный retry создаёт полный 64-byte key-файл. |
| API-01 | Пустой associated data криптографически допустим, но расходится с API contract | Исходный PoC; затем `api_01_empty_context_is_rejected` | Пустой context был принят до исправления; теперь encrypt/decrypt возвращают `InvalidContext`. |
| FORMAT-01 | Отсутствие внешней версии может быть намеренным, а explicit API исключает fallback | `format_01_v2_samples_have_no_fixed_external_header`; просмотр CLI dispatch | Fixed header действительно нет; current downgrade не найден. Оставлено только как future design note. |
| MEMORY-01 | `String` drop освобождает буфер, документация уже ограничивает обещания zeroize | `memory_01_legacy_partial_utf8_error_is_rejected`; safe code review | Error path достижим, explicit zeroize отсутствует. Без unsafe memory inspection извлечение остатка не доказано; current severity остаётся Informational. |

## Детальное описание находок

### CRYPTO-01 — стойкость собственной P1024‑V2/SIV-конструкции не подтверждена

- **Severity:** High
- **Confidence:** Speculative
- **Файл и строки:** `src/v2_permutation.rs:3-111`, функция `round_function`, `permute`; `src/v2_sponge.rs:19-137`, функции `absorb`, `squeeze`, `keyed_state`, `derive_subkey`, `authentication_tag`, `xor_stream`; `src/v2.rs:142-209`, `encrypt_with_random`, `decrypt_bytes`. Для OV1: `src/permutation.rs:77-139`, `src/sponge.rs:21-79`, `src/vault.rs:40-135`.
- **Категория:** нестандартный примитив, нестандартный sponge/MAC/XOF/SIV, assumptions about P1024‑V2.
- **Описание:** 1024-битная 32-раундовая Feistel-перестановка и все режимы поверх неё разработаны в проекте. Тест обратимости показывает только корректность Feistel-инверсии; avalanche-тест и fixed vectors фиксируют поведение реализации. Они не устанавливают нижнюю границу числа раундов, отсутствие дифференциальных/линейных/интегральных/алгебраических различителей, fixed points, симметрий, эквивалентных/related keys, слабых состояний sponge, collision/preimage-атак, tag forgery или IND-CCA/nonce-misuse security композиции.
- **Попытка опровержения:** проверено изменение каждого бинарного байта малого контейнера; все варианты отклонены. В 1 024 вызовах OS-generated nonce не повторился. Повторно прошли existing inverse, fixed-vector, avalanche, stream reversibility, wrong-key/context и forced-nonce-reuse tests. Это опровергает простую unauthenticated область контейнера, очевидную ошибку nonce generation в малой выборке и функциональную необратимость.
- **Условия эксплуатации:** существует практический криптоаналитический distinguisher, восстановление ключа, коллизия/forgery или структурная слабость P1024‑V2 либо её использования; атакующий получает chosen plaintext/ciphertext доступ согласно модели угроз.
- **Пошаговый сценарий атаки:** (1) атакующий собирает пары plaintext/container и выбирает сообщения/context; (2) использует найденную структурную слабость связанного семейства раундовых функций или sponge; (3) различает поток/предсказывает tag, строит forgery либо извлекает сведения о ключе; (4) нарушает конфиденциальность или аутентичность. Это сценарий риска, а не подтверждённый практический exploit.
- **Влияние:** потенциально полная потеря конфиденциальности и/или аутентичности всех V2-сообщений под ключом; для OV1 — риск при миграционном чтении.
- **Доказательство или тест:** `tests/security_audit.rs:132-161`; существующие `src/v2_permutation.rs:130-199`, `src/v2_sponge.rs:139-177`, `src/v2.rs:252-290`; отдельный локальный exact-source probe, результаты которого приведены в разделе `Cryptographic Analysis`. Подтверждены length-class/equality leakage и replay, но практическая key-recovery, new-plaintext recovery или tag-forgery атака не найдена. Поэтому CRYPTO-01 остаётся High-impact/Speculative assurance gap. Avalanche/fixed-vector tests не измеряют security margin и не заменяют независимый криптоанализ.
- **Рекомендуемое исправление:** для реальных данных заменить конструкцию на стандартизованный AEAD/SIV с широким анализом (например, библиотечный misuse-resistant AEAD, если это обязательное свойство). Если образовательная собственная конструкция сохраняется — чётко отделить её типами/форматом, не обещать защиту реальных данных, опубликовать спецификацию и заказать независимый криптоанализ с большим запасом раундов.
- **Риск регрессии после исправления:** высокий — смена примитива меняет формат, vectors, key management и совместимость; нужна версия контейнера и миграция.

### PROTO-01 — отсутствует защита от повторного воспроизведения

- **Severity:** Medium
- **Confidence:** Confirmed
- **Состояние исправления:** добавлены `ReplayGuard`, `decrypt_bytes_once` и `decrypt_text_once`. Guard имеет caller-supplied maximum, запоминает `nonce || tag` только после успешной аутентификации и fail-closed возвращает `ReplayWindowFull`. Stateless API сохранён для совместимости и freshness не даёт.
- **Файл и строки:** `src/v2.rs:173-209`, `decrypt_bytes`; `src/main.rs:55-75`, `decrypt_action`.
- **Категория:** replay, freshness, API.
- **Описание:** контейнер содержит nonce/tag/ciphertext, но не счётчик, timestamp, message ID или состояние получателя. `decrypt_bytes` — чистая по отношению к контейнеру операция: корректный ввод всегда снова проходит ту же проверку тега.
- **Попытка опровержения:** проверено предположение, что nonce/tag или внутренний version state делают вторую доставку недействительной. Один и тот же контейнер был передан `decrypt_bytes` дважды.
- **Условия эксплуатации:** принимающая система связывает успешную расшифровку с эффектом, который нельзя безопасно повторять (команда, платёж, импорт записи, изменение состояния), и атакующий может повторно доставить контейнер.
- **Пошаговый сценарий атаки:** (1) перехватить корректный контейнер; (2) доставить его получателю, где он успешно расшифровывается; (3) повторно отправить тот же байт-в-байт контейнер с тем же context; (4) `decrypt_bytes` снова возвращает plaintext, а приложение повторяет действие.
- **Влияние:** повтор авторизованных операций без знания ключа; конфиденциальность и tag integrity сами по себе replay не предотвращают.
- **Доказательство или тест:** исходный test подтвердил два успешных stateless decrypt. Regression `proto_01_replay_guard_rejects_the_second_delivery` был добавлен до API и не компилировался; после исправления первая доставка успешна, вторая возвращает `ReplayDetected`.
- **Рекомендуемое исправление:** явно документировать, что криптографический слой не обеспечивает freshness; на протокольном уровне аутентифицировать монотонный sequence/message ID в context или plaintext и хранить replay window/набор использованных ID атомарно.
- **Риск регрессии после исправления:** средний — состояние replay-защиты требует персистентности, обработки crash/recovery и политики очистки окна.

### DOS-01 — измеримая обработка максимального неаутентифицированного ввода

- **Severity:** Low (понижена с Medium)
- **Confidence:** Confirmed
- **Файл и строки:** `src/v2.rs:178-200`; `src/v2_encoding.rs:6-11,43-87`; `src/v2_sponge.rs:19-65,101-137`; пределы `src/lib.rs:29-32`.
- **Категория:** CPU/memory denial of service, allocation before authentication.
- **Описание:** строка до `V2_MAX_TEXT_SIZE = 22 369 739` байт декодируется целиком до проверки тега, после чего выделяется `inner` и выполняются stream/MAC. Исходный 64-step `.position()` для каждого символа заменён 256-byte direct table; линейная стоимость полной аутентификации остаётся.
- **Попытка опровержения:** максимальный канонический input из символов `A` был подан в `decrypt_bytes` в release build, чтобы проверить, является ли стоимость практически чрезмерной.
- **Условия эксплуатации:** библиотека/CLI обёрнуты сетевым или многопользовательским сервисом без меньшего лимита, rate limiting и concurrency bound; атакующий может отправлять строки близко к максимуму.
- **Пошаговый сценарий атаки:** (1) сформировать строку близко к `V2_MAX_TEXT_SIZE`; (2) отправлять её параллельно на decrypt; (3) заставить процесс выполнять полный sponge/stream/MAC и удерживать крупные буферы; (4) исчерпать CPU/память или очередь. Поиск по alphabet больше не даёт дополнительного multiplier.
- **Влияние:** один запрос занимает около 0.61 CPU-second на проверенной машине и требует передачи 22.37 MB, поэтому сильного bandwidth-to-CPU amplification не показано. Параллельная сетевая обёртка без rate/concurrency limits всё ещё может истощать CPU/память; в локальном CLI влияние низкое.
- **Доказательство или тест:** `tests/security_audit.rs:339-354`, `dos_01_maximum_syntactically_valid_input_cost`; команда `cargo test --release --test security_audit dos_01_maximum_syntactically_valid_input_cost -- --ignored --nocapture` прошла и напечатала `22369739 ... 608.957ms`. Это единичное локальное измерение, не полный benchmark. Исходная Medium severity не выдержала проверку и понижена.
- **Рекомендуемое исправление:** задавать лимит на уровне вызывающего приложения существенно ниже 16 MiB; ограничить параллелизм/rate; заменить линейный поиск 256-элементной decode-таблицей; рассмотреть потоковое/двухпроходное чтение с жёсткими бюджетами. Для SIV проверка всё равно требует обработки сообщения целиком, поэтому operational limits обязательны.
- **Риск регрессии после исправления:** низкий для decode-таблицы и внешних лимитов; высокий для изменения потокового формата/SIV.

### KEYFILE-01 — проверка key-файла подвержена гонке пути

- **Severity:** Low
- **Confidence:** Confirmed
- **Состояние исправления:** исправлена на Unix. `open` выполняется с `O_NOFOLLOW`, metadata проверяется на открытом дескрипторе, а `dev/inode` сравниваются с первоначально проверенным объектом. Та же последовательность применяется к legacy loader. Криптографический формат не менялся.
- **Файл и строки:** `src/keyfile.rs:55-176`, `open_key_file`, `load_key_file`, `load_legacy_key_file`.
- **Категория:** TOCTOU, symlink/path traversal, ownership.
- **Описание исходного дефекта:** сначала вызывался `symlink_metadata(path)`, затем отдельно `File::open(path)`. Между операциями запись каталога можно было заменить. После исправления следование symlink запрещено при `open`, а identity и metadata проверяются на открытом объекте; проверка владельца остаётся внешней политикой.
- **Попытка опровержения:** обычный symlink на валидный 0600/64-byte key был передан loader и корректно отклонён. Затем конкурентный worker попеременно публиковал hard link на первый файл и symlink на второй, пока основной поток вызывал loader.
- **Условия эксплуатации:** родительский каталог или компонент пути доступен на запись атакующему; процесс имеет возможность открыть подменённую цель. Наиболее значим сценарий привилегированного сервиса; для обычного однопользовательского CLI риск ниже.
- **Пошаговый сценарий атаки:** (1) предоставить путь в контролируемом каталоге; (2) дождаться первой metadata-проверки; (3) заменить directory entry на symlink/другой файл нужной длины и mode; (4) заставить процесс загрузить не тот key material; (5) вызвать DoS, key confusion или, если подставленный ключ известен атакующему и читаем процессом, шифрование под атакующим ключом.
- **Влияние:** key substitution/confusion, отказ в расшифровании; при подходящей модели привилегий — потеря конфиденциальности новых сообщений.
- **Доказательство или тест:** исходный PoC загрузил второй ключ. Затем regression `keyfile_01_path_swap_never_follows_the_symlink` был добавлен с требованием никогда не получать атакующий ключ и упал на исходной реализации. После исправления тот же 10-секундный regression прошёл. Статический symlink также продолжает отклоняться.
- **Рекомендуемое исправление:** открывать с `O_NOFOLLOW`/платформенным эквивалентом, проверять metadata уже открытого дескриптора, владельца и link count по принятой политике; требовать доверенный каталог. Для legacy применять те же проверки.
- **Риск регрессии после исправления:** средний — platform-specific поведение, сетевые ФС и допустимые способы развёртывания key-файла.

### KEYFILE-02 — ошибка записи оставляет блокирующий неполный key-файл

- **Severity:** Low
- **Confidence:** Confirmed
- **Состояние исправления:** исправлена. Ключ записывается во временный `0600` файл в том же каталоге, синхронизируется и публикуется no-clobber hard link только после успеха; существующий target не заменяется. Криптографический формат не менялся.
- **Файл и строки:** `src/keyfile.rs:15-96`, `TemporaryKeyFile`, `create_temporary_key_file`, `create_key_file`.
- **Категория:** partial write, crash consistency, availability.
- **Описание исходного дефекта:** целевой файл создавался напрямую через `create_new`. При ошибке `write_all` или `sync_all` функция возвращала `Io`, но оставляла созданный файл; следующий вызов получал `KeyFileExists`. После исправления эти операции происходят до публикации target.
- **Попытка опровержения:** проверено, удалит ли файл завершение процесса/`File::drop` и сможет ли обычный retry автоматически восстановиться.
- **Условия эксплуатации:** ENOSPC, I/O error, quota, отключение носителя или ошибка sync после создания файла.
- **Пошаговый сценарий атаки/сбоя:** (1) создать условия ошибки записи; (2) вызвать создание ключа; (3) получить `Io` после появления target path; (4) повторить; (5) получить `KeyFileExists`, хотя пригодный ключ не был гарантированно сохранён.
- **Влияние:** отказ в создании ключа и риск путаницы вокруг существования/надёжности файла; автоматическая перезапись правильно запрещена, но восстановление не определено.
- **Доказательство или тест:** regression `keyfile_02_interrupted_write_does_not_publish_the_target` был добавлен до исправления и упал: CLI child с `ulimit -f 0` оставил короткий target. После исправления тот же тест прошёл: target после аварии отсутствует, retry успешно создаёт полный 64-byte key-файл.
- **Рекомендуемое исправление:** атомарно писать во временный файл с `0600` в том же доверенном каталоге, `sync_all`, затем no-clobber rename/link; очищать временный файл при ошибке и fsync каталога. Никогда автоматически не заменять существующий target.
- **Риск регрессии после исправления:** средний — различия атомарного no-replace rename между платформами и cleanup после crash.

### API-01 — пустой context принимается вопреки контракту документации

- **Severity:** Informational (понижена с Low)
- **Confidence:** Confirmed
- **Состояние исправления:** исправлена. Encrypt/decrypt отклоняют пустой context с `InvalidContext`.
- **Файл и строки:** `src/v2.rs:142-150,164-179`; `README.md:62-79`.
- **Категория:** domain separation, API misuse.
- **Описание:** README утверждает «Контекст обязателен», но обе публичные операции проверяют только верхний предел 4096 и принимают пустой slice. Криптографическое framing пустого context однозначно, однако два приложения/типа записи под одним master key и одинаковым пустым context не разделены.
- **Попытка опровержения:** рассмотрен контраргумент, что пустой associated data является допустимым значением, а domain separation обеспечивается только тогда, когда caller действительно задаёт разные context. Тест подтвердил приём пустого context, но не показал нарушение криптографии внутри одного логического домена.
- **Условия эксплуатации:** один key используется несколькими потребителями/типами записей, которые оставили context пустым или выбрали одинаковую строку; семантика plaintext пересекается.
- **Пошаговый сценарий атаки:** (1) получить корректный контейнер из домена A с `context=b""`; (2) передать его домену B, использующему тот же key и `context=b""`; (3) tag проходит; (4) B принимает plaintext A в неправильном назначении.
- **Влияние:** cross-protocol/type confusion и replay между доменами; не является самостоятельным раскрытием plaintext.
- **Доказательство или тест:** исходный PoC принял cross-domain container с `b""`. Regression `api_01_empty_context_is_rejected` был добавлен до новой ошибки и не компилировался; после исправления оба public operations возвращают `InvalidContext`.
- **Рекомендуемое исправление:** либо отклонять пустой context, либо изменить документацию и предоставить типизированный конструктор контекста с фиксированными `application/version/record-type` полями. Запрет пустого значения не предотвращает одинаковые непустые context, поэтому нужна политика уникальности.
- **Риск регрессии после исправления:** низкий/средний — существующие контейнеры с пустым context перестанут открываться.

### FORMAT-01 — внешний V2-контейнер не самоверсионируется

- **Severity:** Informational
- **Confidence:** High
- **Файл и строки:** `src/v2.rs:25,96-131,157-161,173-209`; `src/main.rs:62-75`; `README.md:81-96`.
- **Категория:** algorithm agility, format versioning, downgrade.
- **Описание:** бинарный V2 формат — `nonce || tag || encrypted_inner`; version/flags находятся внутри. `decrypt_bytes` по API всегда предполагает V2, CLI отличает legacy только по открытому `OV1-`. Сейчас legacy encryption отсутствует и ключевые форматы различны, поэтому прямой downgrade не построен. Но будущий V3 без внешнего dispatch envelope потребует эвристик или отдельного API.
- **Попытка опровержения:** проверены 32 V2 sample, CLI dispatch и public API. Все sample имели разные первые 8 binary bytes и не начинались с `OV1-`, но V2 API вызывается явно, а CLI имеет однозначную текущую ветку OV1/V2.
- **Условия эксплуатации:** появление нового алгоритма/формата или несколько декодеров с fallback-логикой.
- **Пошаговый сценарий атаки:** подтверждённого downgrade сейчас нет. Возможный будущий сценарий — модифицированный/старый контейнер направляется в fallback decoder, если интеграция начнёт перебирать версии по ошибкам.
- **Влияние:** риск ошибочного выбора алгоритма, downgrade и неясных ошибок при эволюции системы.
- **Доказательство или тест:** `tests/security_audit.rs:163-179`, `format_01_v2_samples_have_no_fixed_external_header`, PASS; формат собирается с nonce первым (`src/v2.rs:157-160`), версия записана только в encrypted inner (`:99`, проверка `:114`). Подтверждён формат, но текущая downgrade-уязвимость опровергнута; это design debt перед будущей multi-version схемой.
- **Рекомендуемое исправление:** перед следующей несовместимой версией ввести компактный внешний magic/version/algorithm ID и аутентифицировать его как associated data; не использовать unauthenticated fallback после криптографической ошибки.
- **Риск регрессии после исправления:** высокий для формата; потребуется явная миграция и сохранение V2 decoder.

### MEMORY-01 — границы zeroization

- **Severity:** Informational
- **Confidence:** High
- **Файл и строки:** `src/v2.rs:46-79,194-228`; `src/vault.rs:17-37,108-135`; `src/keyfile.rs:54-63,76-88`; `README.md:55-57`.
- **Категория:** secret lifetime, error paths.
- **Описание:** хорошие свойства: `VaultKey`, `DecryptedBytes`, `DecryptedText`, sponge-state и основные временные key/buffer значения zeroize-on-drop или очищаются явно; секретные типы не реализуют `Clone`, `Debug` или `Display`. Ограничения: plaintext печатается в терминал; ОС и allocator могут иметь копии; legacy `read_to_string` error возвращается через `?`/`map_err` без явной очистки частично заполненного `value`. `zeroize` не гарантирует очистку swap/crash dumps/терминала, что README корректно признаёт.
- **Попытка опровержения:** создан legacy file с 64 валидными ASCII bytes и последующим invalid UTF-8 байтом. Loader корректно вернул `InvalidKeyFile`; просмотр safe error path подтвердил, что `value` затем уничтожается обычным `String::drop`, но explicit `zeroize` до drop нет. Без `unsafe`/memory-forensics безопасно доказать чтение остатка после free нельзя.
- **Условия эксплуатации:** локальный атакующий имеет доступ к памяти процесса, swap, crash dump, terminal scrollback или способен вызвать ошибку частичного чтения legacy-key и затем исследовать память.
- **Пошаговый сценарий атаки:** (1) заставить процесс обработать ключ/plaintext; (2) получить расширенный локальный доступ к дампу/терминалу/памяти; (3) искать остаточные копии. Это defense-in-depth сценарий и обычно предполагает уже сильные локальные права.
- **Влияние:** увеличение времени/поверхности присутствия секретов; само по себе не даёт удалённого чтения памяти.
- **Доказательство или тест:** `tests/security_audit.rs:199-215`, `memory_01_legacy_partial_utf8_error_is_rejected`, PASS; отсутствие explicit zeroize на ошибке видно в `src/keyfile.rs:76-80`. Подтверждён достижимый error path, но не извлечение данных. Общие terminal/swap/crash-dump ограничения уже явно документированы, поэтому это не самостоятельная подтверждённая уязвимость.
- **Рекомендуемое исправление:** очистить `value` на всех legacy error paths; минимизировать печать/копии; документировать OS hardening (core dumps, swap, terminal history). Не обещать гарантированное стирание из-за `zeroize`.
- **Риск регрессии после исправления:** низкий.

## Cryptographic Analysis

### Объём и статус анализа

Этот раздел рассматривает только P1024‑V2, sponge/KDF/MAC/XOF и SIV-композицию. Rust style, файловая система и обычные ошибки реализации здесь исключены, кроме порядка проверки тега и представления криптографических полей.

Результат не является утверждением безопасности конструкции. Подтверждённых атак с восстановлением master key, раскрытием нового plaintext или созданием нового принимаемого tag/container не найдено. Подтверждены условные утечки длины и равенства при повторе nonce, а также replay. Стойкость нестандартного примитива, MAC/XOF и полной композиции остаётся неподтверждённой.

### Точное устройство V2 SIV

Обозначения:

- `K` — 64-byte master key;
- `N` — 24-byte открытый nonce;
- `A` — context/associated data, не сохраняемый в контейнере;
- `P` — plaintext;
- `R` — 0–31 random padding bytes;
- `I` — inner message;
- `T` — 32-byte synthetic tag;
- `C` — encrypted inner.

Inner строится в `src/v2.rs:82-108`:

```text
I = 0x02 || 0x00 || LE32(|P|) || P || R
|I| = 32 * ceil((6 + |P|) / 32)
|R| = |I| - 6 - |P|
```

Если `|P| ≡ 26 (mod 32)`, `R` пуст. Во всех остальных классах padding заполняется тем же OS RNG после генерации nonce.

Subkeys выводятся не прямым split master key, а двумя domain-separated вызовами custom sponge KDF (`src/v2_sponge.rs:67-81`). Называть полученные значения независимыми можно было бы только после доказательства PRF/KDF-свойств, которого нет:

```text
Kmac    = KDF(K, "OBSIDIAN-V2-MAC-SUBKEY")
Kstream = KDF(K, "OBSIDIAN-V2-STREAM-SUBKEY")
```

При этом tag и stream создают ещё одно `keyed_state` уже от соответствующего 64-byte subkey и повторяют branch label (`src/v2_sponge.rs:83-118`). В точной функциональной записи:

```text
T = MAC_Kmac(N, A, I)                         // 32 bytes
Z = XOF_Kstream(N, T, A, LE64(|I|), |I|)      // |I| bytes
C = I XOR Z
container = N || T || C
```

MAC absorb sequence:

```text
ALGORITHM(label) → MASTER_KEY(Kmac) → SUBKEY_LABEL(MAC_LABEL)
→ FINAL("derive") → NONCE(N) → CONTEXT(A) → MESSAGE(I) → FINAL("tag")
```

Stream absorb sequence:

```text
ALGORITHM(label) → MASTER_KEY(Kstream) → SUBKEY_LABEL(STREAM_LABEL)
→ FINAL("derive") → NONCE(N) → TAG(T) → CONTEXT(A)
→ LENGTH(LE64(|I|)) → FINAL("stream")
```

По порядку операций это MAC-then-stream-encryption в SIV-парадигме, а не Encrypt-then-MAC: tag вычисляется над plaintext inner до XOR encryption, хранится открыто и одновременно используется как вход stream generation. Это SIV-подобная, но не стандартная SIV-схема: synthetic tag зависит также от внешнего random nonce и случайного padding; поток является custom XOF, а не стандартным CTR/AEAD primitive.

Термин «synthetic IV» здесь относится к роли `T` во входе stream generation, а не к полной замене nonce: `N` независимо входит и в MAC, и в stream transcript. Поэтому формула режима и его последствия при misuse должны оцениваться именно для пары `(N,T)`, а не переноситься автоматически со стандартных deterministic SIV-конструкций.

### Sponge framing, длины и однозначность

Каждый вызов `absorb(D, X)` в `src/v2_sponge.rs:19-51` независимо кодирует:

```text
LE64(D) || LE64(|X|) || X || 0x01 || zero padding
```

до кратности 64 байтам и XOR-ит `0x80` в последний byte. Для каждого блока также вводятся `D`, `block_index + 1` и `!block_index XOR ROL(D,29)` в capacity lanes перед P1024‑V2.

Выводы ручной проверки:

- разные поля имеют разные 64-bit domain constants `0x5632_..._0001`–`...0009` (`src/v2_sponge.rs:5-13`);
- длина каждого поля кодируется до данных; prefix/suffix ambiguity между двумя byte strings не найдена;
- `0x01` marker и final `0x80` различают zero extension и границу последнего блока;
- sequence полей фиксирован кодом, поэтому перестановка nonce/context/message не создаёт то же transcript;
- inner имеет отдельную `LE32` plaintext length, а decrypt дополнительно требует единственный ожидаемый padded length (`src/v2.rs:110-131`);
- полный inner, включая header и random padding, входит в MAC;
- stream отдельно привязан к `|I|`; это избыточно относительно fixed ciphertext length, но не создаёт неоднозначности;
- внешний binary container также разбирается однозначно: первые 24 bytes — `N`, следующие 32 bytes — `T`, весь остаток — `C`, причём `|C|` обязан быть положительным кратным 32;
- custom text encoding проверяет canonical trailing bits, поэтому разные принимаемые строки не являются альтернативными представлениями одного binary container (`src/v2_encoding.rs:73-89,95-113`);
- context является одним непрозрачным byte string. Если caller сам кодирует несколько полей простым concatenation без собственного framing, неоднозначность возможна уже на application level; внутренний `absorb` этого исправить не может.

Прямой collision двух разных корректно закодированных field transcripts не построен. Этот вывод относится к синтаксической однозначности, а не к collision resistance sponge.

### Разделение ключей и доменов

Положительные структурные свойства:

- MAC и stream получают разные 64-byte subkeys через разные ASCII labels (`src/v2_sponge.rs:16-17,76-81`);
- MAC transcript не содержит `TAG`, stream transcript явно содержит `TAG(T)`;
- nonce, context, message, tag, length и finalization используют разные domain constants;
- final labels `"derive"`, `"tag"`, `"stream"` различны;
- algorithm label `"OBSIDIAN-P1024-V2-SIV"` поглощается в каждой keyed branch;
- одинаковый `DOMAIN_NONCE` в MAC и stream применяется после раздельно выведенных subkey/branch states, а не в одном transcript.

Подозрительные/недоказанные аспекты:

- разделение является вычислительным, а не информационно-теоретическим: оно полностью зависит от того, что custom `keyed_state/derive_subkey` ведёт себя как secure PRF/KDF;
- `Kmac/Kstream` затем снова используются как master key того же KDF-подобного `keyed_state`, причём branch label повторяется. Прямой state collision не найден, но эта nested/rekeyed конструкция нестандартна и не имеет reduction;
- domain constants последовательны и связаны простыми XOR-разностями. Для ideal permutation это не обязано быть проблемой, но отсутствие exploitable differential relation у P1024‑V2 не доказано;
- master keys с известным XOR/rotational relation входят в одинаковый public transcript. Related-key resistance KDF и permutation отдельно не анализировалась авторами и не следует из avalanche;
- 512-bit master key не означает 512-bit security. При idealized 512-bit sponge capacity generic birthday bound порядка `2^256`, а authenticity дополнительно ограничена 256-bit tag. Это только верхняя оценка при идеальных предположениях, не доказанная нижняя граница.

### Nonce reuse и детерминированность

При свежем OS RNG encryption вероятностно за счёт 192-bit nonce и, для большинства длин, random padding. Generic collision scale для случайного 192-bit nonce — около `2^96` encryptions, далеко за пределами практических объёмов; это всё равно не заменяет анализ misuse режима.

При фиксированных `K,N,A,I` все дальнейшие операции детерминированы:

```text
same (K,N,A,I) ⇒ same T ⇒ same Z ⇒ same C
```

Но при фиксированных только `K,N,A,P` encryption в общем случае не детерминирован, потому что `R` является частью `I`. Исключение — классы без padding и случаи повторения/коллизии padding. Следовательно, конструкцию нельзя без оговорки описывать ни как полностью deterministic SIV, ни как режим, где повтор nonce всегда сохраняет рандомизацию.

Подтверждённый локальный probe точной композиции показал:

- для двух одинаковых 26-byte plaintext, одинаковых key/context и принудительно повторённого nonce tag и ciphertext полностью совпали;
- для двух разных 26-byte plaintext при том же nonce sampled tags и streams различались;
- `C1 XOR C2 != I1 XOR I2` в этой паре, то есть обычная two-time-pad утечка для разных сообщений не наблюдалась.

Длина 26 выбрана не искусственно: `6 + 26 = 32`, поэтому random padding отсутствует и одного повторённого nonce достаточно для полной детерминированности. То же верно для всех `|P| ≡ 26 (mod 32)`. Для других длин fresh padding обычно меняет `I/T/Z/C`, даже если nonce совпал; если nonce повторился из-за rollback/replay всего RNG state, padding также может повториться.

Количество padding entropy зависит от длины и меняется от 0 до 31 bytes. Поэтому дополнительное сокрытие равенства неравномерно:

- при `|R|=0` одинаковый plaintext немедленно даёт тот же container;
- при `|R|=1` существует только 256 вариантов inner, и collision одинаковых containers для повторяющегося plaintext ожидается уже примерно после `2^4`–`2^5` encryptions под одним nonce/context;
- в общем случае birthday scale повторения padding — порядка `2^(4|R|)` encryptions;
- при rollback полного RNG state nonce и padding могут повториться сразу независимо от `|R|`.

При одинаковых `K,N,A` полное совпадение `T,C` означает тот же candidate inner, поэтому такое совпадение действительно подтверждает равенство plaintext и padding, а не только случайное совпадение transport encoding. Random padding нельзя считать равномерной или гарантированной equality-hiding защитой.

Это соответствует обычной оговорке deterministic/misuse-resistant SIV: повтор nonce не обязан раскрывать XOR разных plaintext, но может раскрывать равенство. Полная nonce-misuse confidentiality здесь не доказана, потому что MAC/XOF/KDF нестандартны.

### Утечка длины

Container раскрывает точный padded inner length:

```text
|container| = 24 + 32 + 32 * ceil((6 + |P|) / 32)
```

Поэтому наблюдатель определяет 32-byte plaintext class. Для inner length `32k`, `k ≥ 2`, plaintext лежит в диапазоне:

```text
32(k - 1) - 5 ≤ |P| ≤ 32k - 6
```

Первый class соответствует `0..=26`. Random padding скрывает содержимое padding, но не этот class. Это подтверждённая метаинформационная утечка, а не восстановление plaintext.

### Аутентификация и выдача plaintext

Decrypt (`src/v2.rs:173-209`) выполняет:

1. parse публичных `N,T,C`;
2. вычисление candidate `I' = C XOR XOF(Kstream,N,T,A,|C|)`;
3. вычисление `T' = MAC(Kmac,N,A,I')`;
4. fixed-length comparison `T == T'`;
5. только после успеха — parse version/flags/declared plaintext length и возврат plaintext.

Candidate plaintext вычисляется до проверки тега, как и требуется для SIV decryption, но API не возвращает его и не разбирает его semantic fields до tag success. Не найдено пути выдачи unauthenticated plaintext.

Порядок также не даёт видимого padding oracle: random padding не валидируется по значению, а version/flags/length проверяются только после valid tag. Для invalid tag возвращается единый `InvalidData`. Возможные microarchitectural/physical side channels не оценивались.

### Malleability, forgery, chosen-plaintext и chosen-ciphertext

Для фиксированных `N,T,A,|C|` stream фиксирован. Поэтому bit flip в `C` даёт такой же bit flip в candidate inner. Однако старый `T` после этого должен быть MAC collision/forgery для изменённого inner. Локальный probe изменял bit отдельно в ciphertext и tag; оба варианта дали несовпадающий recomputed tag. Ранее добавленный `crypto_01_every_binary_byte_is_authenticated_for_a_small_container` также отклонил изменение каждого binary byte одного малого контейнера.

Это не доказывает unforgeability. Только в идеализированной модели равномерного 256-bit tag generic online guessing имел бы вероятность порядка `q/2^256`, а tag collisions ожидались бы около `2^128` запросов; эти числа не являются установленными границами для данной конструкции. Если при одном `N,A,|I|` найдены разные inner с одинаковым `T`, stream также совпадает и возникает `C1 XOR C2 = I1 XOR I2`. Реальная сложность может быть ниже из-за неизвестной слабости custom MAC/permutation; такая слабость не найдена и не исключена.

Chosen-plaintext анализ:

- при fresh nonce одинаковые plaintext обычно дают разные containers;
- при принудительном nonce reuse padless-классы дают equality distinguisher;
- известный plaintext раскрывает stream только для конкретного `(K,N,T,A,|I|)`;
- применить этот stream к другому authenticated message без повторного `T` требует tag collision/forgery;
- разные sampled plaintext при одном nonce дали разные tags/streams, но это только один функциональный эксперимент.

Chosen-ciphertext анализ:

- attacker может выбирать `N,T,C,A` и получает verification bit через `Ok/InvalidData`;
- изменение `C` при сохранении `T` требует MAC forgery;
- изменение `T` одновременно меняет stream, после чего новый candidate inner должен иметь именно attacker-chosen `T`;
- transplant между context/nonce меняет и MAC, и stream transcript;
- truncation/extension меняет stream length и MAC input и не даёт найденного shortcut;
- точный replay корректного container принимается, потому что freshness state отсутствует;
- нового принимаемого ciphertext без key в анализе не построено.

### P1024‑V2: permutation, fixed points, симметрии и диффузия

P1024‑V2 (`src/v2_permutation.rs:72-111`) — 32-round balanced Feistel:

```text
L_(r+1) = R_r
R_(r+1) = L_r XOR F_r(R_r)
```

Поэтому полное преобразование является permutation независимо от обратимости `F_r`; существующий inverse test подтверждает согласованность реализации. `F_r` использует 4 последовательных step над 8×64-bit words, modular additions, odd multiplications, rotations, XOR, shuffle и round-dependent constants. Нелинейность относительно XOR создаётся carry в modular addition и multiplication; multiplication на odd constant при этом обратима modulo `2^64`.

Локальный probe, включивший точный `src/v2_permutation.rs`, дал:

| Проверка | Результат |
|---|---|
| Все 1024 single-bit differences от zero state | Hamming distance min 455, max 561, mean 512.455 из 1024 |
| Раздельно input halves | left mean 512.574, right mean 512.336 |
| Уникальность 1024 полученных output differences | 1024/1024 unique |
| Частота flip каждого output bit по 1024 derivatives | min 455, max 563, ожидаемое среднее 512 |
| 10 000 pseudorandom states | 0 sampled fixed points, 0 sampled 2-cycles |
| Простые symmetries на тех же states | 0 complement, lane-rotation, half-swap relations |
| 512 one-bit-related master keys, 256-bit tag | distance min 105, max 150, mean 127.797; 512 unique tags |
| 1024 one-bit message changes, 256-bit tag | distance min 107, max 151, mean 128.066; 1024 unique tags |
| Один nonce-bit, 1024-bit stream sample | 508 changed bits |

Эти результаты не подтверждают cryptographic security:

- avalanche является необходимым регрессионным признаком, но не исключает high-probability differential/linear trails;
- выборка fixed points практически ничего не говорит о полном пространстве `2^1024`; у random permutation fixed points в принципе ожидаемы;
- проверены только простые complement/lane/half symmetries, не invariant subspaces, rotational-XOR relations или algebraic invariants;
- round functions детерминированы, используют один набор constants и не являются независимо случайными PRF, как предполагают классические Feistel bounds;
- reduced-round distinguishers, minimum active words, differential/linear branch numbers, algebraic degree, boomerang/rebound, meet-in-the-middle и quantum bounds не исследованы;
- 32-round security margin не обоснован сравнением с лучшей атакой.

### Related-key сценарии

Master key поглощается в одинаковое initial state и public framing; attacker с oracle под `K` и `K XOR Δ` получает closely related sponge inputs. Round constants не зависят от key, а subkey labels различают только назначение, не master-key family.

Эксперимент с 512 одно-битовыми `Δ` показал близкую к половине tag bits диффузию и не дал tag collisions. Это опровергает только грубую слабость «один key bit влияет на малую часть tag». Он не исключает:

- related-key differential trails через два framed key blocks;
- equivalent master keys;
- relation между `Kmac` и `Kstream`;
- rotational/complement key classes;
- multi-user attacks на одинаковых contexts/nonces;
- снижение security из-за nested use `KDF(K,label)` → `keyed_state(subkey,label)`.

Практическая related-key атака не построена. Оценить свойство без специализированного внешнего анализа нельзя.

### 1. Подтверждённые атаки и утечки

1. **Length-class leakage:** container раскрывает plaintext length с точностью до 32-byte class.
2. **Equality leakage при nonce reuse:** для `|P| ≡ 26 (mod 32)` одинаковые `K,N,A,P` дают идентичные `T,C`; локальный exact-composition probe это воспроизвёл. При 1-byte padding container collisions ожидаются уже после десятков повторов одного plaintext под тем же nonce; в общем случае padding-collision scale зависит от `|R|`. Условие — атакующий добился повторения nonce.
3. **Replay:** точный valid container может быть принят повторно; это подтверждено `PROTO-01`. SIV/аутентичность сами по себе freshness не дают.

Это не key-recovery, plaintext-recovery или tag-forgery атаки. Подтверждённых атак этих трёх типов в проведённом анализе нет.

### 2. Подозрительные свойства

1. Полностью собственные permutation, sponge, KDF, MAC и XOF без reduction или опубликованного security margin.
2. Связанные deterministic round functions вместо независимо анализируемых Feistel round PRF.
3. Nested rekeying и повтор branch label при построении MAC/stream state; прямой collision не найден, но proof burden повышен.
4. Приемлемость последовательных XOR-related domain constants зависит от достаточной differential resistance permutation; она не установлена.
5. Random padding превращает deterministic SIV в гибридный randomized режим и усложняет точную misuse-security модель; для padless lengths эта дополнительная рандомизация исчезает.
6. 512-bit key может создавать ложное ожидание 512-bit strength, тогда как idealized capacity/tag bounds не выше примерно 256 bits.
7. Context синтаксически framed как один field, но API не задаёт canonical multi-field application encoding.
8. Existing avalanche unit test `src/v2_permutation.rs:153-172` меняет только первые 128 из 1024 input bits; локальный probe расширил покрытие, но не криптоанализ.

### 3. Свойства, которые невозможно оценить без внешнего криптоанализа

1. Реальная PRP security и достаточность 32 rounds P1024‑V2.
2. Лучшие differential, linear, integral, rotational, algebraic, invariant-subspace, boomerang/rebound и meet-in-the-middle attacks.
3. Indifferentiability/PRF bounds sponge при точном rate 512/capacity 512 framing.
4. Collision/preimage/second-preimage security MAC transcript и соответствие 256-bit tag заявленному уровню.
5. Pseudorandomness/related-input security stream XOF и отсутствие correlations между соседними 64-byte squeeze blocks.
6. Related-key и multi-user security KDF/subkey construction.
7. Формальная IND-CPA/IND-CCA и nonce-misuse security полной randomized SIV-композиции с random padding.
8. Фактический запас безопасности относительно reduced-round attacks.
9. Microarchitectural/physical leakage точного permutation implementation и compiler output.

## Этап 1 — карта и архитектура проекта

### Состав репозитория

- `Cargo.toml`, `Cargo.lock`: один package/library+CLI, Rust 2024, MSRV 1.85; прямые зависимости `getrandom = 0.4.3`, `zeroize = 1.9.0`.
- `src/v2.rs`: V2 public API, формат inner/container, encryption/decryption, tag comparison, secret wrappers.
- `src/v2_permutation.rs`: P1024‑V2 — 1024-bit, 32-round balanced Feistel над двумя половинами по 512 бит.
- `src/v2_sponge.rs`: framing/absorb/squeeze, subkey derivation, MAC/tag и stream XOF.
- `src/v2_encoding.rs`: custom unpadded 64-symbol text encoding.
- `src/keyfile.rs`, `src/random.rs`: key generation, key-file I/O, OS RNG abstraction.
- `src/main.rs`: локальный интерактивный CLI; сетевого интерфейса нет.
- `src/container.rs`, `src/encoding.rs`, `src/padding.rs`, `src/permutation.rs`, `src/sponge.rs`, `src/vault.rs`: read-only legacy OV1 decoder.
- `tests/`: corruption, encoding, keyfile, legacy fixed vector и roundtrip tests.
- `build.rs`, `benches/`, `examples/`, workspace members и features отсутствуют. `unsafe` отсутствует.

### Назначение, активы и секреты

Система — экспериментальный учебный консольный шифратор и библиотека для строк/байтов. Основной актив — plaintext. Главный секрет V2 — 64-байтовый master key; legacy — 96 decoded key bytes из 128-символьного файла. Временными секретами являются MAC/stream subkeys, sponge states, decrypted inner/plaintext. Nonce, tag, ciphertext, версия/формат и context не обязаны быть секретными.

### V2 примитивы и размеры

| Элемент | Размер/параметр | Источник |
|---|---:|---|
| Master key | 64 bytes / 512 bits | `src/v2.rs:13,28-49` |
| Nonce | 24 bytes / 192 bits, `getrandom::fill` | `src/v2.rs:14,151`; `src/random.rs:7-18` |
| Synthetic tag | 32 bytes / 256 bits | `src/v2.rs:15`; `src/v2_sponge.rs:83-99` |
| Permutation state | 16 × `u64` = 1024 bits | `src/v2_permutation.rs:38-64` |
| Feistel rounds | 32 | `src/v2_permutation.rs:3,97-111` |
| Sponge rate (по реализации) | 64 bytes / 512 bits | `src/v2_sponge.rs:24,34-49,53-65` |
| Implied capacity | 64 bytes / 512 bits | вторая половина state; это интерпретация конструкции, не доказанная security claim |
| Padding quantum | 32 bytes | `src/v2.rs:16,82-108` |
| Inner header | 6 bytes | version 1, flags 1, LE length 4 |
| Context max | 4096 bytes | `src/v2.rs:18,148-149,178-179` |
| Plaintext max | 16 MiB | `src/lib.rs:29` |

### Формат V2 и последовательность шифрования

Binary container:

```text
nonce[24] || synthetic_tag[32] || encrypted_inner[n * 32]
```

Inner:

```text
version=2[1] || flags=0[1] || plaintext_length_le_u32[4]
|| plaintext || random_padding_to_32_bytes
```

Шифрование (`src/v2.rs:142-170`):

1. Проверить только верхнюю границу context.
2. Получить 24-byte nonce из OS RNG.
3. Построить inner; padding также заполнить OS RNG.
4. Получить отдельный MAC subkey через P1024‑V2 KDF.
5. Вычислить tag от nonce, context и всего inner.
6. Получить отдельный stream subkey; вывести поток из key, nonce, tag, context и inner length.
7. XOR inner с потоком.
8. Конкатенировать nonce/tag/ciphertext и применить custom text encoding.

### Последовательность расшифрования V2

Расшифрование (`src/v2.rs:173-230`):

1. Проверить верхние границы encoded/context.
2. Канонически декодировать текст целиком.
3. Проверить минимальную длину и кратность encrypted inner 32 байтам.
4. Разобрать nonce/tag/ciphertext.
5. Вывести stream из key/nonce/полученного tag/context/length и получить candidate inner.
6. Пересчитать MAC по candidate inner и сравнить 32-byte tag циклом без раннего выхода.
7. Только после успеха проверить encrypted version/flags/length/padded size.
8. Вернуть plaintext в zeroizing wrapper; текстовый API дополнительно проверяет UTF‑8.

Candidate plaintext вычисляется до tag check, что необходимо для данной SIV-композиции, но наружу до проверки не выдаётся. Padding полностью аутентифицирован. Поля framing включают разные 64-bit domain constants, явную длину и `0x01...0x80` padding, поэтому неоднозначного внутреннего кодирования на просмотренном уровне не найдено.

### Legacy OV1

OV1 доступен только через `decrypt_ov1_text` и CLI prefix `OV1-`. Открытый header: magic 8, version 1, algorithm ID 1, reserved 6, salt 32, nonce 32, ciphertext length LE 8; затем ciphertext, tag 32. Ciphertext кратен 512 байтам. Сессия использует 96-byte key, 32-byte salt/nonce, собственную P1024‑V1 state/permutation и stateful ciphertext-absorbing stream/tag. Header и ciphertext аутентифицируются перед возвратом plaintext. Новое OV1 encryption отсутствует.

### Генерация, хранение и удаление ключей

- V2 keys генерируются `getrandom::fill`, 64 bytes; caller-provided nonce API отсутствует, что снижает случайный nonce misuse.
- `VaultKey::from_bytes` принимает любое 64-byte значение, включая низкоэнтропийное; библиотека не может в общем случае проверить энтропию.
- Unix create использует `create_new` и mode `0600`; overwrite запрещён. На non-Unix эквивалентная ACL-проверка отсутствует.
- Load отклоняет symlink, не-файл, неверную длину и Unix group/other mode bits; после исправления KEYFILE-01 Unix loader также использует `O_NOFOLLOW` и сверяет identity открытого файла. Windows reparse points отдельно не проверены.
- Key, decrypted wrappers и внутренние состояния очищаются через `zeroize`; гарантии ограничены MEMORY-01.
- Password-based derivation отсутствует. Пользовательский пароль API не принимает; следовательно, нет salt/KDF для пароля и нельзя считать key-файл производным от пароля.

### Доверенные и недоверенные входы

Доверенные/секретные: корректно сгенерированный master key, политика выбора уникального context, локальная политика прав на каталог key-файла. Недоверенные: encoded container, ciphertext/tag/nonce, legacy header и lengths, plaintext от вызывающего кода, путь к key-файлу (особенно компоненты каталога), содержимое key-файла, CLI stdin, ошибки I/O/RNG. Context аутентифицируется, но его семантическая уникальность остаётся обязанностью caller.

### Внешние поверхности атаки

- Публичные library API `encrypt_*`, `decrypt_*`, `VaultKey::from_bytes`, `keyfile::*`, legacy decrypt.
- CLI stdin/stdout и filesystem paths.
- Text/binary decoders, length parsing, allocation and expensive crypto before authentication.
- Key-file filesystem metadata/open/write/sync operations.
- OS RNG и две прямые зависимости.
- Сетевой интерфейс отсутствует; сетевой риск появляется только при обёртывании library внешним сервисом.

## Этап 2 — модель угроз и требуемые свойства

Принята модель исходного задания: атакующий знает код/алгоритм, видит много ciphertext, знает части plaintext, имеет chosen-plaintext доступ, изменяет/обрезает/повторяет/переставляет контейнеры, отправляет malformed data на decrypt, наблюдает errors/time/memory и добивается nonce reuse, но не знает master key.

| Свойство | Требование | Состояние после аудита |
|---|---|---|
| Конфиденциальность | Не раскрывать plaintext/отношения, кроме допустимой утечки длины-класса; выдерживать chosen plaintext и nonce reuse в заявленных пределах | Зависит от CRYPTO-01; длина раскрывается с точностью до 32-byte inner class; nonce repetition для разных inner меняет tag/stream при предположении PRF. |
| Целостность | Любое изменение nonce/tag/ciphertext/context должно отклоняться | Код аутентифицирует все поля; практическая гарантия зависит от MAC/P1024‑V2. Existing corruption tests покрывают лишь выбранные позиции. |
| Аутентичность | Без key нельзя создать принимаемый новый контейнер | Зависит от непроверенной 256-bit custom MAC construction. |
| Replay protection | Повтор принятого контейнера не должен повторять эффект | Не обеспечено: PROTO-01. |
| Nonce-misuse resistance | Повтор nonce не должен раскрывать XOR plaintext/ключ; допустимые утечки должны быть явно определены | Конструкция включает tag в stream. Тест показывает только два примера разных сообщений. Для одинаковых inner+nonce ciphertext детерминирован; при некоторых длинах random padding отсутствует (например, plaintext length 26), поэтому равенство повторов одинакового plaintext наблюдаемо. Полная misuse security не доказана. |
| Domain separation | MAC, stream, поля и приложения не должны пересекаться | Внутренние constants/labels различны и length-framed; application separation зависит от caller context, пустое значение разрешено (API-01). |
| Forward secrecy | Компрометация текущего long-term key не должна раскрывать старые сообщения, если свойство заявлено | Не заявлена и не обеспечена: один static symmetric key открывает все сохранённые сообщения. |
| Error-oracle resistance | Wrong key/context/corruption должны быть неразличимы | V2 decrypt возвращает `InvalidData` для этих случаев. Public pre-validation timing/size differences остаются наблюдаемыми, но подтверждённого plaintext/tag oracle не найдено. |

## Этап 3 — ручной аудит по классам

### Что проверено и не привело к отдельной подтверждённой находке

- **Nonce/RNG:** V2 nonce генерируется внутри API через `getrandom`; caller не может случайно передать nonce. Ошибка RNG распространяется. Persistent counter нет, но 192 random bits делают случайную коллизию пренебрежимо вероятной при корректной ОС. Компрометация/rollback RNG остаётся внешним предположением.
- **Authentication order:** V2 candidate inner и OV1 inner вычисляются до tag check, но не возвращаются/не парсятся семантически до успешного сравнения. Подтверждённого padding oracle нет.
- **Tag compare:** V2 проходит фиксированные 32 итерации и использует `black_box`; OV1 сравнивает равные fixed-size arrays через max-length loop. Раннего выхода по секретному байту не найдено. Формальной гарантии constant-time на всех компиляторах/CPU нет.
- **Branches/lookups:** в P1024‑V2 нет secret-indexed tables/ветвей; indices и rotations публичны. Integer multiply/rotate timing предполагается constant-time на целевых general-purpose CPU, но не проверялся аппаратно.
- **Integers/bounds:** plaintext/context/container bounds есть; `checked_add`, `try_from`, canonical trailing bits используются. Production `unwrap` отсутствует. Единственный production `expect` в `v2_sponge::absorb` относится к невозможному для реально выделенного slice overflow; API limits дополнительно малы.
- **Unsafe/UB:** `unsafe` отсутствует; raw pointers/FFI отсутствуют.
- **Ambiguous encoding:** V2 decoder отклоняет non-ASCII, длину mod 4 == 1, неизвестные символы и ненулевые unused trailing bits; canonical encoding обеспечен.
- **Truncation/extension/reordering:** container length/multiplicity проверяются, а tag охватывает nonce/context/inner; перестановка ciphertext меняет recovered inner и ожидаемый tag при предположении MAC security.
- **Key separation:** MAC и stream subkeys используют разные labels и domain constants. Криптографическая достаточность KDF остаётся частью CRYPTO-01.
- **Errors:** wrong key, context и corrupted V2 data сходятся в `InvalidData`; размеры отклоняются до криптографии, поэтому timing classes различимы, но не найдено использование этого различия для раскрытия plaintext.
- **Secret API:** `VaultKey` fixed-size, не `Clone`/`Debug`; ошибки нельзя проигнорировать без явного игнорирования `Result`. Plaintext wrapper не выдаётся до auth. `from_bytes` допускает слабые 64-byte keys; это обычный raw-key API, но caller обязан обеспечить entropy.
- **File overwrite:** `create_new` запрещает перезапись существующего key-файла. Вывод plaintext/ciphertext идёт в терминал, key не печатается.

## Этап 4 — автоматические проверки

Команды были объявлены до запуска. Новые инструменты не устанавливались, разрешение на сеть не запрашивалось.

| Команда | Результат |
|---|---|
| `cargo fmt --all -- --check` | PASS, exit 0 |
| `cargo check --all-targets --all-features` | PASS, exit 0 |
| `cargo clippy --all-targets --all-features -- -D warnings` | PASS, exit 0, warnings отсутствуют |
| `cargo test --all-targets --all-features` | PASS: 31 passed, 0 failed, 3 audit PoC ignored in ordinary run |
| `cargo audit` | NOT COMPLETED: `cargo-audit 0.22.2` попытался получить RustSec DB, затем не смог создать lock в read-only `/Users/leonidkornov/.cargo/advisory-db..lock`; сеть не разрешалась |
| `cargo tree -d` | PASS: `warning: nothing to print`, дубликатов для текущей платформы нет |
| `cargo +nightly miri test` | NOT RUN: `unsafe` не найден; установлен только stable toolchain, nightly отсутствует; условие запуска Miri из задания не выполнено |

Полное дерево текущей платформы: `getrandom 0.4.3` → `cfg-if 1.0.4`, `libc 0.2.186`, `r-efi 6.0.0` (target-dependent); `zeroize 1.9.0`. Из-за незавершённого `cargo audit` нельзя утверждать отсутствие известных advisory.

Отдельно запущены ignored regression/PoC:

- `keyfile_01_path_swap_never_follows_the_symlink` — FAIL до исправления, PASS после исправления (10.01 s).
- `keyfile_02_interrupted_write_does_not_publish_the_target` — FAIL до исправления, PASS после исправления.
- `cargo test --release --test security_audit dos_01_maximum_syntactically_valid_input_cost -- --ignored --nocapture` — test PASS, 22 369 739 bytes за 608.957 ms. Обёртка `/usr/bin/time -l` вернула nonzero только из-за запрещённого sandbox-вызова `sysctl kern.clockrate`; сам test завершился успешно.

## 1. Подтверждённые проблемы и дефекты

1. **PROTO-01 (Medium, conditional impact):** replay отсутствует; повторный контейнер снова принимается. Текущий CLI не выполняет state-changing operation, но библиотечный consumer может.
2. **KEYFILE-01 (Low, исправлена на Unix):** path-swap race до исправления реально позволял загрузить второй key-файл; regression после исправления проходит. Проверка Windows reparse points остаётся отдельной задачей.
3. **KEYFILE-02 (Low, исправлена):** target больше не публикуется до полной записи и `sync_all`; crash может оставить только скрытый temporary file.
4. **DOS-01 (Low, deployment-dependent):** предаутентификационная стоимость измерена; сильное amplification не показано.
5. **API-01 (Informational behavior):** пустой context принимается; это не самостоятельная уязвимость без multi-domain key/context reuse.

CRYPTO-01 намеренно не включён в подтверждённые уязвимости: это высокорисковое непроверенное допущение, но практическая криптоатака не построена.

FORMAT-01 и общая часть MEMORY-01 не являются текущими подтверждёнными уязвимостями. FORMAT-01 — future versioning design debt; MEMORY-01 в основном повторяет документированные ограничения `zeroize`. У legacy error path подтверждено лишь отсутствие explicit zeroize, не извлечение остатка.

## 2. Вероятные проблемы, которые ещё нужно проверить

1. Полный независимый криптоанализ CRYPTO-01; текущие tests не могут подтвердить или опровергнуть стойкость.
2. DOS-01 при параллельных запросах, точный peak RSS и отдельный OV1 maximum input; единичный V2 release path измерен.
3. KEYFILE-01 при разных UID/ACL, в привилегированном процессе и на Windows reparse points; Unix regression и legacy code path исправлены.
4. Compiler-level constant-time inspection `fixed_tag_eq`/legacy compare в release builds для каждой целевой архитектуры.
5. KEYFILE-02: cleanup скрытых temporary files после hard crash и crash consistency записи каталога; неполный target regression исправлен.
6. Fuzz/property campaign для больших/случайных контейнеров; новый тест изменяет каждый бинарный байт одного малого контейнера, но не все длины/комбинации.
7. Возможность практического восстановления legacy-key fragment из allocator memory после UTF-8 error.

## 3. Криптографические допущения, не подтверждаемые анализом кода

1. P1024‑V2 после 32 связанных Feistel rounds ведёт себя как secure permutation с достаточным запасом.
2. `round_function` не имеет exploitable differential/linear/algebraic/rotational/related-round структуры, fixed points или слабых классов входов.
3. Sponge с реализованными rate/capacity и framing обеспечивает заявляемые KDF/MAC/XOF свойства.
4. Двойное использование `keyed_state` при derive и затем при MAC/stream не создаёт related-key weakness.
5. 256-bit tag действительно даёт близкую к 256-bit forgery security, а не меньшую из-за конструкции/permutation.
6. SIV-композиция остаётся confidential/authentic при nonce reuse в точной реализованной модели, включая random padding и отсутствие padding для отдельных длин.
7. No secret-dependent microarchitectural leakage у multiplication/rotation и compiler output.
8. OS RNG корректен, не откатывается/не компрометирован и выдаёт независимые key/nonce/padding bytes.
9. OV1 собственная permutation/sponge/tag construction безопасна для миграционного чтения сохранённых данных.

## 4. Что требуется от независимого криптоаналитика

1. Формальная однозначная спецификация P1024‑V2, sponge, KDF, MAC, XOF и полной SIV-композиции, независимая от Rust-кода.
2. Анализ числа раундов и security margin; differential, linear, integral, rotational, impossible differential, invariant subspace, algebraic, meet-in-the-middle/rebound и symmetry/fixed-point исследования.
3. Анализ related-key/subkey derivation и повторного поглощения labels/key material.
4. Sponge bounds для 512-bit rate/capacity, multi-user и multi-target security, collision/preimage/tag-forgery bounds с объёмами данных.
5. Доказательство или reduction полной scheme: nonce-respecting и nonce-misuse confidentiality/authenticity, chosen-ciphertext поведение, equality leakage и влияние random padding.
6. Анализ domain constants/framing на cross-domain collisions и state collisions.
7. Отдельная оценка OV1 перед продолжением migration support.
8. Публичные test vectors и независимая реализация для выявления расхождений спецификации.

## 5. Тесты и инструменты, которые не удалось запустить

- `cargo audit`: advisory DB недоступна для lock/update в sandbox, сеть запрещена.
- Miri: `unsafe` отсутствует и nightly toolchain не установлен; не запускался по условию задания.
- Fuzzing, sanitizers, Loom, valgrind и длительный criterion benchmark не запускались.
- Полный memory-forensics PoC для MEMORY-01 не создавался: безопасное наблюдение freed allocation без `unsafe`/внешнего memory tool невозможно.
- Независимый криптоанализ CRYPTO-01 локальным unit test заменить невозможно.

## 6. Исправления в порядке приоритета

1. **Не использовать V2/OV1 для критичных данных до независимого криптоанализа; для production перейти на стандартный, широко анализируемый AEAD/SIV.**
2. Добавить протокольный message ID/sequence и персистентную replay-защиту там, где decrypt вызывает эффект.
3. Сделать key-file open атомарно защищённым от symlink/TOCTOU, проверять owner/descriptor metadata и доверенность каталога.
4. Сделать создание key-файла crash-consistent через временный файл, sync и atomic no-clobber publish.
5. Ограничить вход/параллелизм на deployment-уровне; измерить parallel worst-case/RSS; заменить линейный alphabet lookup при необходимости.
6. Устранить расхождение context contract: типизированный application/version/record-type context или явная документация, что empty разрешён; определить политику уникальности.
7. До появления V3 спроектировать внешний аутентифицируемый version/algorithm envelope и строгий dispatch без fallback по auth error.
8. Сохранить `tests/security_audit.rs`; добавить regression/property/fuzz/load/fault coverage для непокрытых вариантов и проверить release assembly constant-time compare.
9. Обеспечить локальную RustSec DB/разрешённый запуск `cargo audit` и повторить dependency audit.

## Границы анализа

Аудит был статическим ручным обзором всего предоставленного репозитория, запуском перечисленных локальных команд и адресных audit tests/PoC. Основная реализация в `src/` не изменялась; добавлен только `tests/security_audit.rs`, а отчёт обновлён. Не проводились внешний поиск, публикация кода, полноценный криптоанализ, side-channel измерения, fuzz campaign, аудит ОС/компилятора/dependencies source code или production deployment. Одно измерение времени не является репрезентативным benchmark. Отсутствие дополнительных находок не означает отсутствие уязвимостей.
