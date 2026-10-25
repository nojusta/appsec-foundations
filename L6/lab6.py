from math import gcd
from pathlib import Path

from sympy import factorint, integer_nthroot, randprime

from pagalbines_funkcijos import byte_length, bytes_to_string, int_to_string, string_to_int


VARIANT = 10


def read_variant() -> dict[int, list[int]]:
    variant_file = Path(__file__).with_name("variantai") / f"{VARIANT}.txt"
    sections = {}

    for line in variant_file.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        if line.endswith("."):
            section = int(line[:-1])
            sections[section] = []
        else:
            sections[section].extend(int(value) for value in line.split())

    return sections


def generate_keys(e: int) -> tuple[int, int, int, int]:
    while True:
        p = int(randprime(2**255, 2**256))
        q = int(randprime(2**255, 2**256))
        phi = (p - 1) * (q - 1)

        if p != q and 1 < e < phi and gcd(e, phi) == 1:
            n = p * q
            d = pow(e, -1, phi)
            return p, q, n, d


def encrypt_text(text: str, e: int, n: int) -> int:
    message = string_to_int(text)
    if message >= n:
        raise ValueError("Tekstas per ilgas: pranešimo skaičius turi būti mažesnis už n.")
    return pow(message, e, n)


def recover_small_message(e: int, n: int, ciphertext: int) -> str:
    message, exact = integer_nthroot(ciphertext, e)
    if not exact or message**e >= n:
        raise ValueError("Negalima pritaikyti atakos: reikia tikslios šaknies ir m^e < n.")
    return int_to_string(int(message))


def recover_factored_message(e: int, n: int, ciphertext: int) -> str:
    factors = factorint(n)
    if len(factors) != 2 or any(power != 1 for power in factors.values()):
        raise ValueError("n turi būti dviejų skirtingų pirminių skaičių sandauga.")

    p, q = (int(factor) for factor in factors)
    phi = (p - 1) * (q - 1)
    d = pow(e, -1, phi)
    return int_to_string(pow(ciphertext, d, n))


def remove_pkcs1_padding(block: bytes) -> bytes:
    if not block.startswith(b"\x00\x02"):
        raise ValueError("Neteisinga RSAES-PKCS1-v1_5 bloko pradžia.")

    separator = block.find(b"\x00", 2)
    if separator < 10:
        raise ValueError("Neteisingas RSAES-PKCS1-v1_5 prailginimas.")

    return block[separator + 1:]


def decrypt_pkcs1(ciphertext: int, d: int, n: int) -> str:
    if not 0 <= ciphertext < n:
        raise ValueError("Šifro reikšmė turi būti nuo 0 iki n - 1.")

    message = pow(ciphertext, d, n)
    block = message.to_bytes(byte_length(n), "big")
    if block.startswith(b"\x02"):
        block = b"\x00" + block

    return bytes_to_string(remove_pkcs1_padding(block))


def main() -> None:
    variant = read_variant()
    full_name = input("Įveskite vardą ir pavardę: ")
    e = variant[1][0]
    p, q, n, d = generate_keys(e)
    ciphertext = encrypt_text(full_name, e, n)
    small_message = recover_small_message(*variant[3])
    factored_message = recover_factored_message(*variant[4])
    private_d, private_n, padded_ciphertext = variant[5]
    padded_message = decrypt_pkcs1(padded_ciphertext, private_d, private_n)

    print(f"\nVariantas: {VARIANT}")
    print("\n1. Atsakymas:")
    print(f"p = {p}")
    print(f"q = {q}")
    print(f"Viešasis raktas (e, n): ({e}, {n})")
    print(f"Privatusis raktas (d, n): ({d}, {n})")
    print(f"\n2. Šifras: {ciphertext}")
    print(f"\n3. Atšifruotas tekstas: {small_message}")
    print(f"\n4. Atšifruotas tekstas: {factored_message}")
    print(f"\n5. Atšifruotas tekstas: {padded_message}")


if __name__ == "__main__":
    main()
