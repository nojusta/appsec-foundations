# 9 laboratorinis darbas — AES

## Užduotis

1. Atšifruokite tekstą užšifruotą AES šifru su 3 raundais.
2. Užšifruokite savo pavardę AES šifru su 3 raundais.

## Varianto parinkimas

Užduočių variantai faile `variantai.txt`

`variantas = studento pažymėjimo numeris mod 10 + 1`

## Užduoties failo struktūra

- Variantas
- Raktas (blokai visiems raundams, keyExpansion daryti nereikia)
- Tekstas

## Pagalbinės funkcijos

Pagalbines funkcijas, keitinių bei daugybos lenteles atlikti užduočiai rasite faile `aes_helpers.py`. Konvertavimui skirtos šios funkcijos:

- Raktui ir šifrui konvertuoti į blokus - `byte_string_to_blocks`.

- Atviram tekstui konveruoti į blokus - `string_to_blocks`.

- Blokams konvertuoti į atvirą tekstą - `blocks_to_string`.

- Blokams konveruoti į šifrą - `blocks_to_byte_string`

## Atsakymo pateikimo forma

1. Atšifruotas tekstas
   1. Šifras
   2. Naudotas raktas
2. Programos kodas
