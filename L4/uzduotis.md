# 4 laboratorinis darbas — Slaptažodžių saugojimas

## Užduotis

Rasti slaptažodžius užšifruotus hash'ais surengiant dictionary ataką.

- MD5
- SHA-256
- bcrypt
- scrypt (N = 2^16, r=2, p=1)
- Argon2

## Papildoma užduotis (iki 5 balų)

- Rasti bet kokią nutekintą duomenų bazę, kurioje slaptažodžiai buvo hash'uojami.
- Nulaužti bent 20 slaptažodžių
- Procesą aprašyti.

## Varianto parinkimas

- Užduočių variantai faile variantai.zip
- variantas = studento pažymėjimo numeris mod 10 + 1

## Užduoties failo struktūra

- Algoritmo pavadinimas, hash, salt (jei buvo naudotas)
- MD5 ir SHA256 laužimui naudoti failą rockyou.txt. bcrypt, scrypt ir Argon2 - rockyou_1000.txt.

## Pagrindinės užduoties atsakymo įvedimo forma

- MD5 slaptažodis
- SHA-256 slaptažodis
- bcrypt slaptažodis
- scrypt slaptažodis
- Argon2 slaptažodis
- Programos kodas

## Papildomos užduoties aprašyme nurodyti

- Duomenų aprašymas (kokia įmonė, kada nutekinta, kiek slaptažodžių nutekinta ir pan.)
- Kur radote duomenis
- Kokiu algoritmu buvo hash'uota
- Bent 20 slaptažodžių, kuriuos pavyko nulaužti
- Aprašymą pateikti .docx arba .pdf formatu
