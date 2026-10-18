from __future__ import annotations

import argparse
import fcntl
import getpass
import json
import os
import re
import tempfile
import time
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path

import pyotp
import qrcode
from argon2 import PasswordHasher
from argon2.exceptions import VerificationError
from cryptography.fernet import Fernet

INTERVAL = 30
MAX_FAILURES = 5
LOCK_SECONDS = 60
SETUP_TTL = 600
PH = PasswordHasher(time_cost=2, memory_cost=19456, parallelism=1)


class AuthError(Exception):
    """Laukiama nesėkmė; CLI parodo tik šios klaidos paaiškinimą."""


def private_write(path: Path, data: bytes) -> None:
    """Rašymas per laikiną 0600 failą; os.replace atominiu būdu pakeičia turinį."""
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd, tmp = tempfile.mkstemp(dir=path.parent)
    try:
        with os.fdopen(fd, 'wb') as stream:
            stream.write(data)
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


@dataclass
class Setup:
    secret: str
    created_at: float

    def uri(self, username: str) -> str:
        return pyotp.TOTP(self.secret, interval=INTERVAL).provisioning_uri(
            name=username, issuer_name='VU ISP L5')


class MFA:
    def __init__(self, state_path: Path, key_path: Path):
        self.state_path, self.key_path = state_path, key_path
        self.state = json.loads(state_path.read_text()) if state_path.exists() else None

    def cipher(self, *, create=False) -> Fernet:
        if not self.key_path.exists():
            if not create:
                raise AuthError('Nerastas šifravimo raktas. Seno rakto pakeisti nauju negalima.')
            self.key_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            # O_EXCL neleidžia netyčia perrašyti jau egzistuojančio rakto.
            fd = os.open(self.key_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, 'wb') as stream:
                stream.write(Fernet.generate_key())
        return Fernet(self.key_path.read_bytes().strip())

    def save(self):
        private_write(self.state_path, json.dumps(
            self.state, ensure_ascii=False, indent=2).encode())

    def create(self, username: str, password: str):
        if self.state is not None:
            raise AuthError('Demonstracinė paskyra jau sukurta.')
        if not username.strip() or len(password) < 12:
            raise AuthError('Įveskite vardą ir bent 12 simbolių slaptažodį.')
        self.cipher(create=True)
        self.state = dict(username=username.strip(), password_hash=PH.hash(password),
                          mfa_enabled=False, totp_secret_encrypted=None,
                          last_used_step=-1, failed_attempts=0, locked_until=0)
        self.save()

    def guard(self, now):
        if self.state is None:
            raise AuthError('Pirma sukurkite demonstracinę paskyrą.')
        if self.state['locked_until'] > now:
            raise AuthError('Per daug bandymų. Pabandykite po 60 sekundžių.')
        if self.state['locked_until']:
            self.state.update(failed_attempts=0, locked_until=0)
            self.save()

    def failure(self, now):
        self.state['failed_attempts'] += 1
        if self.state['failed_attempts'] >= MAX_FAILURES:
            self.state['locked_until'] = now + LOCK_SECONDS
        self.save()
        raise AuthError('Autentifikavimas nepavyko arba kodas jau panaudotas.')

    def password_ok(self, username, password, now):
        self.guard(now)
        try:
            verified = PH.verify(self.state['password_hash'], password)
        except VerificationError:
            verified = False
        if not verified or username != self.state['username']:
            self.failure(now)

    def begin_setup(self, username, password, *, now=None) -> Setup:
        now = time.time() if now is None else now
        self.password_ok(username, password, now)
        if self.state['mfa_enabled']:
            raise AuthError('TOTP jau aktyvuotas. Ši komanda jo neperrašo.')
        # Paslaptis lieka atmintyje iki pirmo teisingo kodo patvirtinimo.
        return Setup(pyotp.random_base32(), now)

    def confirm_setup(self, setup: Setup, code: str, *, now=None):
        now = time.time() if now is None else now
        self.guard(now)
        if self.state['mfa_enabled']:
            raise AuthError('TOTP jau aktyvuotas.')
        if now < setup.created_at or now - setup.created_at > SETUP_TTL:
            raise AuthError('Aktyvavimo laikas baigėsi. Pradėkite iš naujo.')
        if not re.fullmatch(r'[0-9]{6}', code) or not pyotp.TOTP(
                setup.secret, interval=INTERVAL).verify(code, for_time=now):
            self.failure(now)
        self.state.update(
            totp_secret_encrypted=self.cipher().encrypt(setup.secret.encode()).decode(),
            mfa_enabled=True, last_used_step=int(now // INTERVAL),
            failed_attempts=0, locked_until=0)
        self.save()

    def login(self, username, password, code, *, now=None):
        now = time.time() if now is None else now
        self.password_ok(username, password, now)
        if not self.state['mfa_enabled']:
            raise AuthError('Prisijungimas nesuteiktas: pirmiausia aktyvuokite TOTP.')
        # Serveriui būtina atkurti paslaptį, todėl ji šifruojama, ne hash'inama.
        secret = self.cipher().decrypt(self.state['totp_secret_encrypted'].encode()).decode()
        step = int(now // INTERVAL)
        valid = bool(re.fullmatch(r'[0-9]{6}', code)) and pyotp.TOTP(
            secret, interval=INTERVAL).verify(code, for_time=now)
        # Tik dabartinis 30 s intervalas; jokio ±1 intervalo toleravimo.
        if not valid or step <= self.state['last_used_step']:
            self.failure(now)
        self.state.update(last_used_step=step, failed_attempts=0, locked_until=0)
        self.save()
        return True


@contextmanager
def exclusive_lock(state_path: Path):
    """Mac ir Linux skirtas vietinis užraktas apima visą CLI operaciją."""
    path = state_path.parent / '.mfa.lock'
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd = os.open(path, os.O_CREAT | os.O_RDWR, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        yield
    except BlockingIOError:
        raise AuthError('Kitas programos procesas jau veikia.') from None
    finally:
        os.close(fd)


def main():
    parser = argparse.ArgumentParser(description='VU ISP L5: slaptažodis ir TOTP')
    parser.add_argument('command', choices=['create', 'enable', 'login'])
    parser.add_argument('--data-dir', type=Path,
                        default=Path(__file__).parent / '.runtime')
    args = parser.parse_args()
    key = Path(os.environ.get('MFA_KEY_FILE',
                             Path.home() / '.config/appsec-l5/fernet.key'))
    qr_path = args.data_dir / 'setup_qr.png'
    try:
        with exclusive_lock(args.data_dir / 'user.json'):
            app = MFA(args.data_dir / 'user.json', key)
            username = input('Naudotojo vardas: ').strip()
            password = getpass.getpass('Slaptažodis: ')
            if args.command == 'create':
                if password != getpass.getpass('Pakartokite slaptažodį: '):
                    raise AuthError('Slaptažodžiai nesutampa.')
                app.create(username, password)
                print('Paskyra sukurta. Dabar paleiskite: python mfa.py enable')
            elif args.command == 'enable':
                setup = app.begin_setup(username, password)
                # QR kuriamas lokaliai: paslaptis nesiunčiama išorinei QR paslaugai.
                import io
                buf = io.BytesIO()
                qrcode.make(setup.uri(username)).save(buf, format='PNG')
                private_write(qr_path, buf.getvalue())
                print(f'QR failas: {qr_path.resolve()}')
                print('Atidarykite QR paveikslėlį ir nuskaitykite autentifikatoriumi.')
                try:
                    code = getpass.getpass('Programėlės 6 skaitmenų kodas: ')
                    app.confirm_setup(setup, code.strip())
                    print('TOTP aktyvuotas. Prisijungimui palaukite naujo kodo.')
                finally:
                    # QR turi paslaptį, todėl po bandymo pašalinamas.
                    qr_path.unlink(missing_ok=True)
            else:
                code = getpass.getpass('TOTP kodas: ')
                app.login(username, password, code.strip())
                print('Prisijungimas sėkmingas: patikrinti abu faktoriai.')
        return 0
    except (AuthError, ValueError) as exc:
        print(f'Klaida: {exc}')
        return 1
    except KeyboardInterrupt:
        print('\nOperacija nutraukta.')
        return 1
    except EOFError:
        print('Trūksta įvesties. Paleiskite programą terminale.')
        return 1
    except Exception as exc:
        # Nei paslapčių, nei traceback su jautriomis reikšmėmis į ekraną nerašome.
        print(f'Konfigūracijos arba failo klaida ({type(exc).__name__}).')
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
