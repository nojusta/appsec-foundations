# 7 laboratorinis darbas — Skaitmeninis parašas

## Užduotis:

1. Sukurti sertifikatą, kuriame būtų įrašytas jūsų vardas, pavardė ir RSA viešasis raktas
2. Pasirašyti sertifikato piršto antspaudą savo RSA privačiuoju raktu
3. Pasirašyti sertifikato piršto antspaudą su laiko žyma savo RSA privačiuoju raktu

## Taisyklės

Užduočiai atlikti galite naudoti 6 Laboratoriniame darbe sugeneruotą RSA raktą.

Sertifikato piršto antspaudui apskaičiuoti naudokite SHA256. Pasitikrinti ar failo hash teisingas galite https://md5file.com/calculator

Laiko žyma turi būti Unix formatu (Unix timestamp).

Pagalbines funkcijas skirtas konvertuoti baitus į skaičius ir skaičius į baitus rasite faile pagalbines_funkcijos.py

## Atsakymo įvedimo forma:

1. Failas sertifikatas.txt. Šio failo pirmos trys eilutės turi atrodyti taip:

   1. Vardas Pavardė
   2. Viešojo rakto n
   3. Viešojo rakto e

2. Parašas.

   1. Sertifikato piršto antspaudas - SHA256(sertifikatas.txt)
   2. Piršto antspaudo parašas (dešimtainis skaičius)

3. Parašas su laiko žyma ts10 - laiko žyma sekundėmis.

   1. Sertifikato ir laiko žymos piršto antspaudas - SHA256(SHA256(sertifikatas.txt) || ts16), čia ts16 - ts10 konvertuota į baitus.
   2. ts10
   3. Sertifikato ir laiko žymos piršto antspaudo parašas (dešimtainis skaičius)

Programos kodas
