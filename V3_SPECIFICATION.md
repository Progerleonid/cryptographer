# Obsidian Vault V3 — техническая спецификация

Статус: экспериментальная учебная конструкция, версия 3. Спецификация задаёт
формат однозначно, но не является доказательством криптографической стойкости.

## 1. Представление

- `u64` означает целое по модулю `2^64`.
- Сложение и умножение `u64` выполняются по модулю `2^64`.
- Все целые в byte transcript кодируются little-endian.
- `ROTL(x,n)` и `ROTR(x,n)` — циклические вращения 64-битного слова.
- `||` — конкатенация, `XOR` — побитовое исключающее ИЛИ.

## 2. P1024-V3

Состояние состоит из 16 слов `u64` и делится на половины `L` и `R` по восемь
слов. Выполняется 48 balanced Feistel rounds:

```text
L[r + 1] = R[r]
R[r + 1] = L[r] XOR F(r, R[r])
```

`F` выполняет четыре шага. Каждый шаг состоит из нелинейного слоя, отдельного
пятиветвевого линейного diffusion layer полного бинарного ранга 512 и
фиксированного shuffle. Точные множители, rotation
tables, shuffle tables, initial state и публичный алгоритм генерации констант
нормативно определены в `src/v3_permutation.rs`.

Раундовые константы зависят от `(round, step, lane)` и публичного seed
`0x4f4253494449414e` (`OBSIDIAN`). Они не являются ключами.

Feistel-инверсия:

```text
R[r] = L[r + 1]
L[r] = R[r + 1] XOR F(r, L[r + 1])
```

Фиксированный вектор `P1024-V3(0^1024)` находится в unit test
`fixed_vector_defines_p1024_v3`.

## 3. Duplex framing

Размер state — 1024 бита:

```text
rate = lanes[0..8]     = 512 bits
capacity = lanes[8..16] = 512 bits
```

Поле `(domain, data)` кодируется:

```text
LE64(domain) || LE64(len(data)) || data || 0x01 || 0x00... || final_xor_0x80
```

Результат дополняется до ненулевого количества 64-байтовых блоков. Для каждого
блока `j`:

```text
rate ^= block
lane[8]  ^= domain
lane[9]  ^= j + 1
lane[14] ^= ROTL(len(data), 17)
lane[15] ^= NOT(j) XOR ROTL(domain, 31) XOR 0x0180
state = P1024-V3(state)
```

При squeeze выдаются первые 64 байта state. Перед каждым следующим выходным
блоком выполняется P1024-V3.

Домены и labels нормативно перечислены в `src/v3_duplex.rs`.

## 4. Подключи

Master key `K` содержит 64 случайных байта. Для каждого назначения выводится
отдельный 64-байтовый подключ:

```text
Kmac    = KDF(K, "OBSIDIAN-V3-MAC-SUBKEY")
Kstream = KDF(K, "OBSIDIAN-V3-STREAM-SUBKEY")
Kcommit = KDF(K, "OBSIDIAN-V3-COMMITMENT-SUBKEY")
```

KDF поглощает algorithm label, master key, label назначения и final label в
разных доменах, затем извлекает 64 байта.

## 5. Внутреннее сообщение

Для plaintext `M`:

```text
I = 0x03 || 0x00 || 0x0000 || LE32(len(M)) || M || random_padding
```

Длина:

```text
len(I) = 32 * (floor((8 + len(M)) / 32) + 1)
```

Поэтому random padding всегда имеет длину от 1 до 32 байт и заполняется OS RNG.

## 6. Контейнер и SIV-композиция

Публичный бинарный заголовок:

```text
H = 4f 42 53 56 33 00 01 00
```

Генерируется случайный 24-байтовый nonce `N`.

```text
Q = Trunc128(MAC_Kcommit(H, N, context))
T = Trunc256(MAC_Kmac(H, Q, N, context, LE64(len(I)), I))
Z = XOF_Kstream(H, Q, N, T, context, LE64(len(I)))
C = I XOR Z[0..len(I)]
```

Бинарный контейнер:

```text
H[8] || Q[16] || N[24] || T[32] || C[32 * n]
```

Текстовый контейнер:

```text
"OV3-" || Encode64(binary_container)
```

`Encode64` использует алфавит:

```text
ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz123456789-_~
```

Padding `=` отсутствует, unused trailing bits обязаны быть нулевыми.

## 7. Расшифрование

1. Проверить `OV3-`, canonical encoding, размеры, `H` и кратность ciphertext 32.
2. Вычислить ожидаемый `Q` и сравнить все 16 байт без раннего выхода.
3. Получить candidate `I = C XOR Z`.
4. Пересчитать `T` по полному candidate `I`.
5. Сравнить все 32 байта тега без раннего выхода.
6. Только после успешного тега проверить inner version/flags/reserved/length.
7. Вернуть plaintext; candidate inner очищается через `zeroize`.

Wrong key, context, commitment, tag и повреждённый ciphertext возвращают одну
ошибку `InvalidData`.

## 8. Совместимость и границы

- Публичное шифрование всегда создаёт V3.
- `decrypt_*` выбирает V3 только при точном `OV3-`; иначе пробует V2.
- OV1 читается только отдельной функцией `decrypt_ov1_text`.
- Максимальный plaintext: 16 MiB.
- Максимальный context: 4096 байтов, пустой запрещён.
- In-memory replay token: `nonce || tag`.

## 9. Неподтверждённые допущения

Без независимого анализа не установлены PRP security P1024-V3, sponge
indifferentiability, MAC unforgeability, XOF pseudorandomness, related-key и
multi-user bounds, а также IND-CCA/nonce-misuse security полной композиции.
Анализаторы и тесты в репозитории являются средствами поиска дефектов, а не
доказательствами этих свойств.
