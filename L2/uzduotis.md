# 2 laboratorinis darbas — Viženerio šifras

## Užduotys

1. Atšifruoti Viženerio šifrą, kai duotas raktas.
2. Rasti raktą, naudotą šifravimui.

## Varianto parinkimas

- Variantas apskaičiuojamas taip: `studento pažymėjimo numeris mod 10 + 1`.
- Sprendžiamas failas `variantai/<variantas>.txt`

## Taisyklės

- Naudojama abėcėlė: `aąbcčdeęėfghiįyjklmnoprsštuųūvzž`.
- Simboliai, kurių nėra abėcėlėje, turi likti nepakeisti.
- Didžiosios raidės laikomos abėcėlės dalimi ir turi išlikti didžiosios.
- Neabėcėliniams simboliams raktas netaikomas ir jo pozicija nepasislenka. Pavyzdžiui, šifruojant `a b c` raktu `de`, taikomos rakto raidės yra `d e d`, o ne `d e d e d`.

## Užduoties failo struktūra

- 1.
- Užšifruotas tekstas
- 2.
- Raktas
- Užšifruotas tekstas, kuriam reikia rasti raktą

## Pateikimo forma

- Variantas
- Atšifruotas tekstas
- Raktas
- Programos kodas
