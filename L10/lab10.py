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


def decrypt_ecb(blocks, round_keys):
    return [decrypt_block(block, round_keys) for block in blocks]


def decrypt_cbc(blocks, round_keys, iv):
    result = []
    previous = iv
    for block in blocks:
        result.append(add_round_key(decrypt_block(block, round_keys), previous))
        previous = block
    return result


def decrypt_pcbc(blocks, round_keys, iv):
    result = []
    previous = iv
    for block in blocks:
        plaintext = add_round_key(decrypt_block(block, round_keys), previous)
        result.append(plaintext)
        previous = add_round_key(plaintext, block)
    return result


def decrypt_cfb(blocks, round_keys, iv):
    result = []
    previous = iv
    for block in blocks:
        result.append(add_round_key(block, encrypt_block(previous, round_keys)))
        previous = block
    return result


def decrypt_ofb(blocks, round_keys, iv):
    result = []
    previous = iv
    for block in blocks:
        previous = encrypt_block(previous, round_keys)
        result.append(add_round_key(block, previous))
    return result


def read_variant(variant=VARIANT):
    variant_file = Path(__file__).with_name("variantai") / f"{variant}.txt"
    lines = [line.strip() for line in variant_file.read_text(encoding="utf-8").splitlines() if line.strip()]
    key = lines[0].split("=", 1)[1].strip()
    iv = lines[1].split("=", 1)[1].strip()
    ciphertexts = {int(lines[index][:-1]): lines[index + 1] for index in range(2, len(lines), 2)}

    if len(bytes.fromhex(key)) != 64 or len(bytes.fromhex(iv)) != 16:
        raise ValueError("Reikia keturių rakto blokų ir vieno 16 baitų IV.")
    if set(ciphertexts) != {1, 2, 3, 4, 5}:
        raise ValueError("Reikia penkių šifrų, sunumeruotų nuo 1 iki 5.")
    if any(len(bytes.fromhex(cipher)) % 16 for cipher in ciphertexts.values()):
        raise ValueError("Šifrų ilgiai turi dalytis iš 16 baitų.")

    return (
        helpers.byte_string_to_blocks(key),
        helpers.byte_string_to_blocks(iv)[0],
        [helpers.byte_string_to_blocks(ciphertexts[index]) for index in range(1, 6)],
    )


def main() -> None:
    round_keys, iv, ciphertexts = read_variant()
    plaintexts = [
        decrypt_ecb(ciphertexts[0], round_keys),
        decrypt_cbc(ciphertexts[1], round_keys, iv),
        decrypt_pcbc(ciphertexts[2], round_keys, iv),
        decrypt_cfb(ciphertexts[3], round_keys, iv),
        decrypt_ofb(ciphertexts[4], round_keys, iv),
    ]

    for index, (mode, blocks) in enumerate(zip(("ECB", "CBC", "PCBC", "CFB", "OFB"), plaintexts), 1):
        print(f"{index}. AES-{mode}: {helpers.blocks_to_string(blocks)}")


if __name__ == "__main__":
    main()
