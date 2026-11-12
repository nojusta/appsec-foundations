# appsec-foundations

Python lab exercises for an Information Security Fundamentals university course.

- **L1:** Caesar cipher.
- **L2:** Vigenère cipher and frequency analysis.
- **L4:** Password hashing and dictionary attacks.
- **L5:** Multi-factor authentication with TOTP.
- **L6:** RSA key generation, encryption and basic attacks.
- **L7:** RSA digital signatures and timestamps.
- **L8:** Diffie–Hellman and baby-step giant-step.
- **L9:** Three-round AES implementation.
- **L10:** AES modes: ECB, CBC, PCBC, CFB and OFB.

Lab 3 covers SQL injection on TryHackMe; no code is included here.

Each lab directory contains its task description (`uzduotis.md`), code and any included input data. Run scripts from the repository root, for example:

```bash
python3 L10/lab10.py
```

Some labs require additional Python packages. L5 lists its dependencies in `L5/requirements.txt`; L4 also needs the local `rockyou.txt` wordlist, which is not committed.
