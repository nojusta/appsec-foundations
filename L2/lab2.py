from pathlib import Path


ALPHABET = "aąbcčdeęėfghiįyjklmnoprsštuųūvzž"
ALPHABET_SIZE = len(ALPHABET)

VARIANT = 10

FREQUENCIES = {
    "a": 11.19, "ą": 0.54, "b": 1.48, "c": 0.60, "č": 0.43, "d": 2.58,
    "e": 5.62, "ę": 0.17, "ė": 1.66, "f": 0.35, "g": 1.79, "h": 0.28,
    "i": 12.96, "į": 0.48, "y": 1.43, "j": 2.38, "k": 4.17, "l": 3.50,
    "m": 3.58, "n": 5.14, "o": 6.74, "p": 2.73, "r": 5.67, "s": 7.88,
    "š": 1.13, "t": 5.33, "u": 4.59, "ų": 1.26, "ū": 0.40, "v": 2.65,
    "z": 0.35, "ž": 0.80,
}


def shift_character(character: str, shift: int) -> str:
    lowercase_character = character.lower()
    if lowercase_character not in ALPHABET:
        return character

    position = ALPHABET.index(lowercase_character)
    shifted_character = ALPHABET[(position + shift) % ALPHABET_SIZE]
    return shifted_character.upper() if character.isupper() else shifted_character


def vigenere_decrypt(text: str, key: str) -> str:
    key_characters = [character.lower() for character in key if character.lower() in ALPHABET]
    result = []
    key_position = 0

    for character in text:
        lowercase_character = character.lower()
        if lowercase_character not in ALPHABET:
            result.append(character)
            continue

        shift = ALPHABET.index(key_characters[key_position % len(key_characters)])
        result.append(shift_character(character, -shift))
        key_position += 1

    return "".join(result)


def alphabet_characters(text: str) -> str:
    return "".join(character.lower() for character in text if character.lower() in ALPHABET)


def coincidence_index(text: str) -> float:
    if len(text) < 2:
        return 0

    repeated_pairs = sum(text.count(character) * (text.count(character) - 1) for character in ALPHABET)
    return repeated_pairs / (len(text) * (len(text) - 1))


def key_length_score(text: str, key_length: int) -> float:
    columns = [text[position::key_length] for position in range(key_length)]
    return sum(coincidence_index(column) for column in columns) / key_length


def find_key_length(text: str) -> int:
    return max(range(1, 21), key=lambda length: key_length_score(text, length))


def caesar_score(text: str, shift: int) -> float:
    decrypted_text = "".join(shift_character(character, -shift) for character in text)
    return sum(
        (decrypted_text.count(character) - len(text) * FREQUENCIES[character] / 100) ** 2
        / (len(text) * FREQUENCIES[character] / 100)
        for character in ALPHABET
    )


def find_key(text: str) -> str:
    letters = alphabet_characters(text)
    key_length = find_key_length(letters)
    key = []

    for position in range(key_length):
        column = letters[position::key_length]
        shift = min(range(ALPHABET_SIZE), key=lambda current_shift: caesar_score(column, current_shift))
        key.append(ALPHABET[shift])

    return "".join(key)


def read_variant() -> tuple[str, str, str]:
    variant_file = Path(__file__).with_name("variantai") / f"{VARIANT}.txt"
    lines = variant_file.read_text(encoding="utf-8").splitlines()
    second_part = next(index for index, line in enumerate(lines) if line.strip() == "2.")
    first_part = [line.strip() for line in lines[:second_part] if line.strip() not in {"", "1."}]
    first_ciphertext, known_key = first_part
    second_ciphertext = "\n".join(lines[second_part + 1:]).lstrip("\n")
    return first_ciphertext, known_key, second_ciphertext


def main() -> None:
    first_ciphertext, known_key, second_ciphertext = read_variant()
    first_plaintext = vigenere_decrypt(first_ciphertext, known_key)
    discovered_key = find_key(second_ciphertext)

    print(f"Variantas: {VARIANT}")
    print(f"Atšifruotas tekstas: {first_plaintext}")
    print(f"Raktas: {discovered_key}")


if __name__ == "__main__":
    main()
