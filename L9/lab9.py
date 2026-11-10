from pathlib import Path

import aes_helpers as helpers


VARIANT = 10


def add_round_key(block, key):
    return [[block[row][column] ^ key[row][column] for column in range(4)] for row in range(4)]


def sub_bytes(block, inverse=False):
    table = helpers.sboxInv if inverse else helpers.sbox
    return [[table[value] for value in row] for row in block]


def shift_rows(block, inverse=False):
    result = []
    for index, row in enumerate(block):
        shift = -index if inverse else index
        result.append(row[shift:] + row[:shift])
    return result


def mix_columns(block, inverse=False):
    result = [[0] * 4 for _ in range(4)]
    for column in range(4):
        a, b, c, d = (block[row][column] for row in range(4))
        if inverse:
            values = [
                helpers.mult_e[a] ^ helpers.mult_b[b] ^ helpers.mult_d[c] ^ helpers.mult_9[d],
                helpers.mult_9[a] ^ helpers.mult_e[b] ^ helpers.mult_b[c] ^ helpers.mult_d[d],
                helpers.mult_d[a] ^ helpers.mult_9[b] ^ helpers.mult_e[c] ^ helpers.mult_b[d],
                helpers.mult_b[a] ^ helpers.mult_d[b] ^ helpers.mult_9[c] ^ helpers.mult_e[d],
            ]
        else:
            values = [
                helpers.mult_2[a] ^ helpers.mult_3[b] ^ c ^ d,
                a ^ helpers.mult_2[b] ^ helpers.mult_3[c] ^ d,
                a ^ b ^ helpers.mult_2[c] ^ helpers.mult_3[d],
                helpers.mult_3[a] ^ b ^ c ^ helpers.mult_2[d],
            ]
        for row in range(4):
            result[row][column] = values[row]
    return result


def encrypt_block(block, round_keys):
    state = add_round_key(block, round_keys[0])
    for key in round_keys[1:-1]:
        state = sub_bytes(state)
        state = shift_rows(state)
        state = mix_columns(state)
        state = add_round_key(state, key)

    state = sub_bytes(state)
    state = shift_rows(state)
    return add_round_key(state, round_keys[-1])


def decrypt_block(block, round_keys):
    state = add_round_key(block, round_keys[-1])
    for key in reversed(round_keys[1:-1]):
        state = shift_rows(state, inverse=True)
        state = sub_bytes(state, inverse=True)
        state = add_round_key(state, key)
        state = mix_columns(state, inverse=True)

    state = shift_rows(state, inverse=True)
    state = sub_bytes(state, inverse=True)
    return add_round_key(state, round_keys[0])


def read_variant() -> tuple[str, str]:
    variant_file = Path(__file__).with_name("variantai.txt")
    lines = [line.strip() for line in variant_file.read_text(encoding="utf-8").splitlines() if line.strip()]
    start = lines.index(f"{VARIANT}.")
    key, ciphertext = lines[start + 1:start + 3]

    if len(bytes.fromhex(key)) != 64:
        raise ValueError("Trims raundams reikia keturių 16 baitų rakto blokų.")
    if len(bytes.fromhex(ciphertext)) % 16:
        raise ValueError("Šifro ilgis turi dalytis iš 16 baitų.")
    return key, ciphertext


def main() -> None:
    key, ciphertext = read_variant()
    round_keys = helpers.byte_string_to_blocks(key)
    encrypted_blocks = helpers.byte_string_to_blocks(ciphertext)
    plaintext_blocks = [decrypt_block(block, round_keys) for block in encrypted_blocks]
    plaintext = helpers.blocks_to_string(plaintext_blocks)

    surname = input("Įveskite pavardę: ")
    surname_blocks = helpers.string_to_blocks(surname)
    surname_cipher = [encrypt_block(block, round_keys) for block in surname_blocks]

    print(f"Atšifruotas tekstas: {plaintext}")
    print(f"Šifras: {helpers.blocks_to_byte_string(surname_cipher)}")
    print(f"Naudotas raktas: {key}")


if __name__ == "__main__":
    main()
