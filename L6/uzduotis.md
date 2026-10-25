# 6 laboratorinis darbas — RSA

## Užduotys

1. Sugeneruoti RSA kriptosistemos viešąjį ir privatųjį raktą, kai duotas e, o p ir q 256 bitų ilgio.
2. Užšifruokite savo vardą ir pavardę 1 užduotyje gautu viešuoju raktu.
3. Nulaužkite slaptaraštį c užšifruotą viešuoju raktu (e, n), kai žinoma, kad me < n. Duotas viešasis raktas.
4. Nulaužkite slaptaraštį c užšifruotą viešuoju raktu (e, n), kai žinoma, kad vienas iš n daliklių yra mažas (40 bitų). Duotas viešasis raktas.
5. Atšifruokite slaptaraštį c prailgintą RSAES-PKCS1-v1_5 schema užšifruotą viešuoju raktu (e, n). Duotas privatusis raktas.

## Taisyklės

- Tekstai koduojami UTF-8 koduote.
- Pagalbinės funkcijos, skirtos konvertuoti tekstą į skaičių, faile `pagalbines_funkcijos.py`

## Varianto parinkimas

- Užduočių variantai faile `variantai.zip`. Spręsti užduotį esančią faile `variantas.txt`
- `variantas = studento pažymėjimo numeris mod 10 + 1`

## Užduoties failo struktūra

### 1.

- e

### 2.

- (e, n)
- c

### 3.

- (e, n)
- c

### 4.

- (d, n)
- c

## Atsakymo įvedimo forma

1. Atsakymas:
   1. p reikšmė
   2. q reikšmė
   3. (e, n)
   4. (d, n)
2. Šifras
3. Atšifruotas tekstas
4. Atšifruotas tekstas
5. Atšifruotas tekstas
6. Programos kodas
