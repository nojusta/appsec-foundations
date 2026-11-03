from math import isqrt
from pathlib import Path

from sympy import factorint, randprime


VARIANT = 10


def read_variant() -> dict[int, dict[str, int]]:
    variant_file = Path(__file__).with_name("variantai") / f"{VARIANT}.txt"
    sections = {}

    for line in variant_file.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        if line.endswith("."):
            section = int(line[:-1])
            sections[section] = {}
        else:
            name, value = line.split("=")
            sections[section][name.strip()] = int(value)

    return sections


def shared_secret(g: int, p: int, a: int, b: int) -> int:
    client_public = pow(g, a, p)
    server_public = pow(g, b, p)
    client_secret = pow(server_public, a, p)
    server_secret = pow(client_public, b, p)

    if client_secret != server_secret:
        raise ValueError("Kliento ir serverio paslaptys nesutampa.")
    return client_secret


def baby_step_giant_step(g: int, p: int, x: int) -> int:
    m = isqrt(p - 1)
    if m * m < p - 1:
        m += 1

    steps = {}
    factor = pow(g, m, p)
    value = 1

    for j in range(m):
        steps.setdefault(value, j)
        value = value * factor % p

    inverse = pow(g, -1, p)
    value = x % p

    for i in range(m):
        if value in steps:
            a = (m * steps[value] + i) % (p - 1)
            if pow(g, a, p) == x % p:
                return a
        value = value * inverse % p

    raise ValueError("Diskretusis logaritmas nerastas.")


def is_generator(g: int, p: int) -> bool:
    return all(pow(g, (p - 1) // int(q), p) != 1 for q in factorint(p - 1))


def generate_prime(g: int, bits: int) -> int:
    while True:
        p = int(randprime(2**(bits - 1), 2**bits))
        if is_generator(g, p):
            return p


def main() -> None:
    variant = read_variant()
    secret = shared_secret(**variant[1])
    exponent = baby_step_giant_step(**variant[2])
    generator = 2
    prime = generate_prime(generator, 100)

    print(f"1. Bendra paslaptis: {secret}")
    print(f"2. Diskretusis logaritmas a: {exponent}")
    print(f"3. Pirminis skaičius p: {prime}")


if __name__ == "__main__":
    main()
