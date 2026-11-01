from hashlib import sha256
from pathlib import Path
from time import time

from pagalbines_funkcijos import bytes_to_int, int_to_bytes


# RSA raktas iš 6 laboratorinio darbo.
E = 59341
N = 10108304313500788102413639865719476857910303351860656792734354372993679769504448362185341438780935780519125336480378267373823874556550653151979806020874557
D = 9989234787959643684834105744856365108467602655159377759719721763049078529907956871739284357362914890052708212270682134040992240918568598890892604892822341


def sign_fingerprint(fingerprint: bytes) -> int:
    return pow(bytes_to_int(fingerprint), D, N)


def main() -> None:
    full_name = input("Įveskite vardą ir pavardę: ")
    certificate_file = Path(__file__).with_name("sertifikatas.txt")
    certificate_file.write_bytes(f"{full_name}\n{N}\n{E}\n".encode("utf-8"))

    fingerprint = sha256(certificate_file.read_bytes()).digest()
    signature = sign_fingerprint(fingerprint)

    timestamp = int(time())
    timestamped_fingerprint = sha256(fingerprint + int_to_bytes(timestamp)).digest()
    timestamped_signature = sign_fingerprint(timestamped_fingerprint)

    print("\n2. Parašas:")
    print(f"Sertifikato piršto antspaudas: {fingerprint.hex()}")
    print(f"Piršto antspaudo parašas: {signature}")
    print("\n3. Parašas su laiko žyma:")
    print(f"Sertifikato ir laiko žymos piršto antspaudas: {timestamped_fingerprint.hex()}")
    print(f"ts10: {timestamp}")
    print(f"Sertifikato ir laiko žymos piršto antspaudo parašas: {timestamped_signature}")


if __name__ == "__main__":
    main()
