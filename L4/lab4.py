from pathlib import Path
import hashlib

import bcrypt
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError


VARIANT = 10


def passwords(filename: str):
    dictionary = Path(__file__).with_name(filename)
    with dictionary.open("rb") as file:
        for password in file:
            yield password.rstrip(b"\r\n")


def read_variant() -> dict[str, tuple[str, ...]]:
    variant_file = Path(__file__).with_name("variantai") / f"{VARIANT}.txt"
    hashes = {}

    for line in variant_file.read_text(encoding="utf-8").splitlines():
        algorithm, values = line.split(" ", maxsplit=1)
        hashes[algorithm.lower()] = tuple(values.split(", "))

    return hashes


def find_hash(password_list, hash_function, target: str, salt: str) -> str | None:
    for password in password_list:
        digest = hash_function(password + salt.encode()).hexdigest()
        if digest == target:
            return password
    return None


def find_bcrypt(password_list, target: str) -> str | None:
    target_bytes = target.encode()

    for password in password_list:
        if len(password) <= 72 and bcrypt.checkpw(password, target_bytes):
            return password
    return None


def find_scrypt(password_list, target: str, salt: str) -> str | None:
    target_bytes = bytes.fromhex(target)
    salt_bytes = salt.encode()

    for password in password_list:
        digest = hashlib.scrypt(
            password,
            salt=salt_bytes,
            n=2**16,
            r=2,
            p=1,
            dklen=len(target_bytes),
        )
        if digest == target_bytes:
            return password
    return None


def find_argon2(password_list, target: str) -> str | None:
    password_hasher = PasswordHasher()

    for password in password_list:
        try:
            if password_hasher.verify(target, password):
                return password
        except VerifyMismatchError:
            continue
    return None


def main() -> None:
    hashes = read_variant()
    md5_hash, md5_salt = hashes["md5"]
    sha256_hash, sha256_salt = hashes["sha-256"]
    bcrypt_hash = hashes["bcrypt"][0]
    scrypt_hash, scrypt_salt = hashes["scrypt"]
    argon2_hash = hashes["argon2"][0]

    md5_password = find_hash(passwords("rockyou.txt"), hashlib.md5, md5_hash, md5_salt)
    sha256_password = find_hash(passwords("rockyou.txt"), hashlib.sha256, sha256_hash, sha256_salt)
    bcrypt_password = find_bcrypt(passwords("rockyou_1000.txt"), bcrypt_hash)
    scrypt_password = find_scrypt(passwords("rockyou_1000.txt"), scrypt_hash, scrypt_salt)
    argon2_password = find_argon2(passwords("rockyou_1000.txt"), argon2_hash)

    print(f"MD5 slaptažodis: {display_password(md5_password)}")
    print(f"SHA-256 slaptažodis: {display_password(sha256_password)}")
    print(f"bcrypt slaptažodis: {display_password(bcrypt_password)}")
    print(f"scrypt slaptažodis: {display_password(scrypt_password)}")
    print(f"Argon2 slaptažodis: {display_password(argon2_password)}")


def display_password(password: bytes | None) -> str:
    return password.decode("utf-8", errors="replace") if password else "Nerastas"


if __name__ == "__main__":
    main()
