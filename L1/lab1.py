ALPHABET = "aąbcčdeęėfghiįyjklmnoprsštuųūvzž"
ALPHABET_SIZE = len(ALPHABET)

VARIANT = 10 
ENCRYPTION_TEXT = "Nuliūdęs kaip žemes pardavęs."
ENCRYPTION_SHIFT = 17
DECRYPTION_TEXT = "Sąųuėpę ąh sejifi gąėąžpą."
DECRYPTION_SHIFT = 21


def shift_character(character: str, shift: int) -> str:
    lowercase_character = character.lower()
    if lowercase_character not in ALPHABET:
        return character

    original_position = ALPHABET.index(lowercase_character)
    shifted_character = ALPHABET[(original_position + shift) % ALPHABET_SIZE]
    return shifted_character.upper() if character.isupper() else shifted_character


def caesar_transform(text: str, shift: int) -> str:
    return "".join(shift_character(character, shift) for character in text)


def caesar_encrypt(text: str, shift: int) -> str:
    return caesar_transform(text, shift)


def caesar_decrypt(text: str, shift: int) -> str:
    return caesar_transform(text, -shift)


def caesar_brute_force(text: str) -> list[tuple[int, str]]:
    return [
        (shift, caesar_decrypt(text, shift))
        for shift in range(ALPHABET_SIZE)
    ]


def main() -> None:
    encrypted_text = caesar_encrypt(ENCRYPTION_TEXT, ENCRYPTION_SHIFT)
    decrypted_text = caesar_decrypt(DECRYPTION_TEXT, DECRYPTION_SHIFT)

    print(f"Variantas: {VARIANT}")
    print(f"1. Užšifruotas tekstas: {encrypted_text}")
    print(f"2. Atšifruotas tekstas: {decrypted_text}")


if __name__ == "__main__":
    main()
