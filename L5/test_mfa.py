"""Automatiniai saugumo ir funkcijų bandymai; nenaudoja tikrų paskyrų."""
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import pyotp
from cryptography.fernet import Fernet, InvalidToken
from mfa import MFA, AuthError, Setup, exclusive_lock, main

PASSWORD = 'Demo!Slaptazodis2026'
START = 1800000000


class MFATests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        root = Path(self.tmp.name)
        self.state = root / 'data/user.json'
        self.key = root / 'keys/fernet.key'
        self.app = MFA(self.state, self.key)
        self.app.create('nojustest', PASSWORD)
        self.setup = self.app.begin_setup('nojustest', PASSWORD, now=START)

    def code(self, seconds=0):
        return pyotp.TOTP(self.setup.secret).at(START + seconds)

    def enabled(self):
        self.app.confirm_setup(self.setup, self.code(), now=START)

    def test_01_enrollment_requires_correct_code(self):
        """Netaisyklingas kodas neaktyvuoja TOTP."""
        with self.assertRaises(AuthError):
            self.app.confirm_setup(self.setup, 'abc123', now=START)
        self.assertFalse(MFA(self.state, self.key).state['mfa_enabled'])

    def test_02_enrollment_confirmed_and_encrypted(self):
        """Aktyvavimas patvirtinamas, paslaptis ir slaptažodis JSON neatskleisti."""
        self.enabled()
        raw = self.state.read_text()
        self.assertNotIn(self.setup.secret, raw)
        self.assertNotIn(PASSWORD, raw)
        self.assertIn('$argon2id$', raw)
        self.assertTrue(self.app.state['mfa_enabled'])
        encrypted = self.app.state['totp_secret_encrypted']
        self.assertEqual(Fernet(self.key.read_bytes()).decrypt(encrypted.encode()).decode(),
                         self.setup.secret)
        self.assertEqual(self.state.stat().st_mode & 0o777, 0o600)
        self.assertEqual(self.key.stat().st_mode & 0o777, 0o600)

    def test_03_both_factors_succeed_after_restart(self):
        """Prisijungimas teisingais abiem faktoriais veikia ir iš naujo įkėlus failą."""
        self.enabled()
        self.assertTrue(MFA(self.state, self.key).login(
            'nojustest', PASSWORD, self.code(30), now=START+30))

    def test_04_wrong_password_rejected(self):
        """Teisingas TOTP nekompensuoja klaidingo slaptažodžio."""
        self.enabled()
        with self.assertRaises(AuthError):
            self.app.login('nojustest', 'wrong', self.code(30), now=START+30)

    def test_05_wrong_totp_rejected(self):
        """Teisingas slaptažodis nekompensuoja klaidingo TOTP."""
        self.enabled()
        bad = '000000' if self.code(30) != '000000' else '111111'
        with self.assertRaises(AuthError):
            self.app.login('nojustest', PASSWORD, bad, now=START+30)

    def test_06_expired_and_future_codes_rejected(self):
        """Priimamas tik dabartinio intervalo kodas."""
        self.enabled()
        for code in [self.code(30), self.code(90)]:
            self.assertNotEqual(code, self.code(60))
            with self.assertRaises(AuthError):
                self.app.login('nojustest', PASSWORD, code, now=START+60)

    def test_07_replay_rejected_after_restart(self):
        """Tas pats priimtas kodas negali būti panaudotas dar kartą."""
        self.enabled()
        self.app.login('nojustest', PASSWORD, self.code(30), now=START+30)
        with self.assertRaises(AuthError):
            MFA(self.state, self.key).login(
                'nojustest', PASSWORD, self.code(30), now=START+31)

    def test_08_five_failures_lock_and_expiry(self):
        """Blokavimas išlieka po perkrovimo, o po 60 s baigiasi."""
        self.enabled()
        for _ in range(5):
            with self.assertRaises(AuthError):
                self.app.login('nojustest', 'wrong', self.code(30), now=START+30)
        loaded = MFA(self.state, self.key)
        with self.assertRaisesRegex(AuthError, 'Per daug'):
            loaded.login('nojustest', PASSWORD, self.code(30), now=START+31)
        self.assertTrue(loaded.login('nojustest', PASSWORD, self.code(90), now=START+90))

    def test_09_no_login_without_mfa(self):
        """Paskyros sukūrimas dar nesuteikia prieigos be TOTP."""
        with self.assertRaises(AuthError):
            self.app.login('nojustest', PASSWORD, self.code(), now=START)

    def test_10_setup_expires_and_cannot_overwrite(self):
        """Aktyvavimo laikas ribotas, aktyvus faktorius neperrašomas."""
        with self.assertRaises(AuthError):
            self.app.confirm_setup(self.setup, self.code(630), now=START+630)
        self.enabled()
        with self.assertRaises(AuthError):
            self.app.begin_setup('nojustest', PASSWORD, now=START+30)

    def test_11_missing_or_wrong_key_rejected(self):
        """Pametus arba pakeitus raktą, paslaptis neatkuriama."""
        self.enabled()
        other = Path(self.tmp.name) / 'wrong.key'
        with self.assertRaises(AuthError):
            MFA(self.state, other).login('nojustest', PASSWORD, self.code(30), now=START+30)
        self.assertFalse(other.exists())
        other.write_bytes(Fernet.generate_key())
        with self.assertRaises(InvalidToken):
            MFA(self.state, other).login('nojustest', PASSWORD, self.code(30), now=START+30)

    def test_12_fernet_detects_tampering(self):
        """Pakeisto užšifruoto turinio vientisumo patikra nesėkminga."""
        self.enabled()
        encrypted = self.app.state['totp_secret_encrypted']
        pos = len(encrypted)//2
        char = 'A' if encrypted[pos] != 'A' else 'B'
        self.app.state['totp_secret_encrypted'] = encrypted[:pos]+char+encrypted[pos+1:]
        self.app.save()
        with self.assertRaises(InvalidToken):
            self.app.login('nojustest', PASSWORD, self.code(30), now=START+30)

    def test_13_uri_and_account_checks(self):
        """QR URI atkuria teisingą paslaptį; vartotojo vardas ir slaptažodžio ilgis tikrinami."""
        token = pyotp.parse_uri(self.setup.uri('nojustest'))
        self.assertEqual(token.secret, self.setup.secret)
        self.assertEqual(token.issuer, 'VU ISP L5')
        with self.assertRaises(AuthError):
            self.app.begin_setup('wrong', PASSWORD, now=START)
        with self.assertRaises(AuthError):
            self.app.create('duplicate', PASSWORD)
        another = MFA(Path(self.tmp.name)/'other.json', self.key)
        with self.assertRaises(AuthError):
            another.create('nojustest', 'short')

    def test_14_file_lock_prevents_concurrent_operation(self):
        """Lygiagretus procesas negali apeiti vienkartinio kodo patikros."""
        with exclusive_lock(self.state):
            with self.assertRaises(AuthError):
                with exclusive_lock(self.state):
                    pass

    def test_15_cli_setup_and_login(self):
        """CLI tikrina abu faktorius, QR failą sukuria ir po aktyvavimo pašalina."""
        root = Path(self.tmp.name)
        env = {'MFA_KEY_FILE': str(self.key)}
        def confirm(prompt):
            self.assertTrue((self.state.parent/'setup_qr.png').exists())
            return self.code()
        with patch.dict('os.environ', env), patch('sys.argv',
                ['mfa.py','enable','--data-dir',str(self.state.parent)]), \
                patch('builtins.input', return_value='nojustest'), \
                patch('mfa.getpass.getpass', side_effect=[PASSWORD, self.code()]), \
                patch('mfa.time.time', return_value=START), \
                patch('mfa.pyotp.random_base32', return_value=self.setup.secret):
            self.assertEqual(main(), 0)
        self.assertFalse((self.state.parent/'setup_qr.png').exists())
        with patch.dict('os.environ', env), patch('sys.argv',
                ['mfa.py','login','--data-dir',str(self.state.parent)]), \
                patch('builtins.input', return_value='nojustest'), \
                patch('mfa.getpass.getpass', side_effect=[PASSWORD, self.code(30)]), \
                patch('mfa.time.time', return_value=START+30):
            self.assertEqual(main(), 0)


if __name__ == '__main__':
    unittest.main(verbosity=2)
