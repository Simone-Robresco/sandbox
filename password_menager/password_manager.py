#!/usr/bin/env python3
"""
Gestore password da CLI in stile "assistente" - AES-256 CBC puro Python,
nessuna dipendenza esterna (solo libreria standard).

- All'avvio chiede la password principale.
- Un piccolo "biglietto" (header) e' salvato cifrato nel json: se la
  password e' giusta si vede "==============", se e' sbagliata si vede
  la stringa cifrata grezza (nessun messaggio esplicito "password sbagliata").
- Scrivi "bye" per bloccare e tornare alla richiesta della password.
- Scrivi "bye bye" alla richiesta della password per chiudere il programma.
"""

import json
import base64
import getpass
import hashlib
import os
from pathlib import Path

DB_FILE = Path(__file__).parent / "passwords.json"
SALT_KEY = "_salt"
HEADER_KEY = "_header"
HEADER_TEXT = "=============================="
KEY_LEN = 32          # AES-256
PBKDF2_ITERATIONS = 200_000
BLOCK_SIZE = 16


# ======================================================================
# Implementazione AES pura (FIPS-197) - encrypt/decrypt di un blocco 16B
# ======================================================================

_SBOX = [
0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16]

_INV_SBOX = [0] * 256
for _i, _v in enumerate(_SBOX):
    _INV_SBOX[_v] = _i

_RCON = [0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36,0x6c,0xd8,0xab,0x4d]


def _gmul(a, b):
    p = 0
    for _ in range(8):
        if b & 1:
            p ^= a
        hi = a & 0x80
        a = (a << 1) & 0xff
        if hi:
            a ^= 0x1b
        b >>= 1
    return p


def _key_expansion(key):
    Nk = len(key) // 4
    Nr = Nk + 6
    Nb = 4
    w = [list(key[4 * i:4 * i + 4]) for i in range(Nk)]
    for i in range(Nk, Nb * (Nr + 1)):
        temp = list(w[i - 1])
        if i % Nk == 0:
            temp = temp[1:] + temp[:1]
            temp = [_SBOX[b] for b in temp]
            temp[0] ^= _RCON[i // Nk - 1]
        elif Nk > 6 and i % Nk == 4:
            temp = [_SBOX[b] for b in temp]
        w.append([w[i - Nk][j] ^ temp[j] for j in range(4)])
    round_keys = []
    for r in range(Nr + 1):
        rk = []
        for c in range(4):
            rk.extend(w[r * 4 + c])
        round_keys.append(rk)
    return round_keys, Nr


def _add_round_key(state, rk):
    return [[state[r][c] ^ rk[c * 4 + r] for c in range(4)] for r in range(4)]


def _sub_bytes(state, box):
    return [[box[state[r][c]] for c in range(4)] for r in range(4)]


def _shift_rows(state):
    return [state[r][r:] + state[r][:r] for r in range(4)]


def _inv_shift_rows(state):
    return [state[r][-r:] + state[r][:-r] if r else state[r][:] for r in range(4)]


def _mix_columns(state):
    new = [[0] * 4 for _ in range(4)]
    for c in range(4):
        col = [state[r][c] for r in range(4)]
        new[0][c] = _gmul(col[0], 2) ^ _gmul(col[1], 3) ^ col[2] ^ col[3]
        new[1][c] = col[0] ^ _gmul(col[1], 2) ^ _gmul(col[2], 3) ^ col[3]
        new[2][c] = col[0] ^ col[1] ^ _gmul(col[2], 2) ^ _gmul(col[3], 3)
        new[3][c] = _gmul(col[0], 3) ^ col[1] ^ col[2] ^ _gmul(col[3], 2)
    return new


def _inv_mix_columns(state):
    new = [[0] * 4 for _ in range(4)]
    for c in range(4):
        col = [state[r][c] for r in range(4)]
        new[0][c] = _gmul(col[0], 14) ^ _gmul(col[1], 11) ^ _gmul(col[2], 13) ^ _gmul(col[3], 9)
        new[1][c] = _gmul(col[0], 9) ^ _gmul(col[1], 14) ^ _gmul(col[2], 11) ^ _gmul(col[3], 13)
        new[2][c] = _gmul(col[0], 13) ^ _gmul(col[1], 9) ^ _gmul(col[2], 14) ^ _gmul(col[3], 11)
        new[3][c] = _gmul(col[0], 11) ^ _gmul(col[1], 13) ^ _gmul(col[2], 9) ^ _gmul(col[3], 14)
    return new


def _bytes_to_state(b):
    return [[b[c * 4 + r] for c in range(4)] for r in range(4)]


def _state_to_bytes(state):
    out = bytearray(16)
    for c in range(4):
        for r in range(4):
            out[c * 4 + r] = state[r][c]
    return bytes(out)


def _aes_encrypt_block(block, round_keys, Nr):
    state = _bytes_to_state(block)
    state = _add_round_key(state, round_keys[0])
    for rnd in range(1, Nr):
        state = _sub_bytes(state, _SBOX)
        state = _shift_rows(state)
        state = _mix_columns(state)
        state = _add_round_key(state, round_keys[rnd])
    state = _sub_bytes(state, _SBOX)
    state = _shift_rows(state)
    state = _add_round_key(state, round_keys[Nr])
    return _state_to_bytes(state)


def _aes_decrypt_block(block, round_keys, Nr):
    state = _bytes_to_state(block)
    state = _add_round_key(state, round_keys[Nr])
    for rnd in range(Nr - 1, 0, -1):
        state = _inv_shift_rows(state)
        state = _sub_bytes(state, _INV_SBOX)
        state = _add_round_key(state, round_keys[rnd])
        state = _inv_mix_columns(state)
    state = _inv_shift_rows(state)
    state = _sub_bytes(state, _INV_SBOX)
    state = _add_round_key(state, round_keys[0])
    return _state_to_bytes(state)


def _pkcs7_pad(data: bytes) -> bytes:
    pad_len = BLOCK_SIZE - (len(data) % BLOCK_SIZE)
    return data + bytes([pad_len]) * pad_len


def _pkcs7_unpad(data: bytes) -> bytes:
    pad_len = data[-1]
    if pad_len < 1 or pad_len > BLOCK_SIZE or data[-pad_len:] != bytes([pad_len]) * pad_len:
        raise ValueError("Padding non valido")
    return data[:-pad_len]


def aes_cbc_encrypt(plaintext: bytes, key: bytes, iv: bytes) -> bytes:
    round_keys, Nr = _key_expansion(key)
    data = _pkcs7_pad(plaintext)
    out = bytearray()
    prev = iv
    for i in range(0, len(data), BLOCK_SIZE):
        block = bytes(a ^ b for a, b in zip(data[i:i + BLOCK_SIZE], prev))
        enc = _aes_encrypt_block(block, round_keys, Nr)
        out.extend(enc)
        prev = enc
    return bytes(out)


def aes_cbc_decrypt(ciphertext: bytes, key: bytes, iv: bytes) -> bytes:
    round_keys, Nr = _key_expansion(key)
    out = bytearray()
    prev = iv
    for i in range(0, len(ciphertext), BLOCK_SIZE):
        block = ciphertext[i:i + BLOCK_SIZE]
        dec = _aes_decrypt_block(block, round_keys, Nr)
        out.extend(a ^ b for a, b in zip(dec, prev))
        prev = block
    return _pkcs7_unpad(bytes(out))


# ======================================================================
# Gestione file JSON
# ======================================================================

def load_db() -> dict:
    if DB_FILE.exists():
        with open(DB_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    return {}


def save_db(db: dict) -> None:
    with open(DB_FILE, "w", encoding="utf-8") as f:
        json.dump(db, f, indent=4, ensure_ascii=False)


def get_or_create_salt(db: dict) -> bytes:
    if SALT_KEY in db:
        return base64.b64decode(db[SALT_KEY])
    salt = os.urandom(16)
    db[SALT_KEY] = base64.b64encode(salt).decode("utf-8")
    return salt


# ======================================================================
# Derivazione chiave e cifratura
# ======================================================================

def derive_key(master_password: str, salt: bytes) -> bytes:
    return hashlib.pbkdf2_hmac("sha256", master_password.encode("utf-8"), salt,
                                PBKDF2_ITERATIONS, dklen=KEY_LEN)


def encrypt_text(plain_text: str, key: bytes) -> str:
    iv = os.urandom(BLOCK_SIZE)
    ct = aes_cbc_encrypt(plain_text.encode("utf-8"), key, iv)
    return base64.b64encode(iv + ct).decode("utf-8")


def decrypt_text(enc_text: str, key: bytes) -> str:
    raw = base64.b64decode(enc_text)
    iv, ct = raw[:BLOCK_SIZE], raw[BLOCK_SIZE:]
    pt = aes_cbc_decrypt(ct, key, iv)
    return pt.decode("utf-8")


def check_header(db: dict, key: bytes) -> str:
    """Ritorna la riga di separazione decifrata se la password e' giusta,
    altrimenti ritorna la stringa cifrata cosi' com'e' (nessun errore esplicito)."""
    enc_header = db.get(HEADER_KEY)
    if not enc_header:
        return HEADER_TEXT
    try:
        dec = decrypt_text(enc_header, key)
        if dec == HEADER_TEXT:
            return HEADER_TEXT
    except (ValueError, UnicodeDecodeError, IndexError):
        pass
    return enc_header


# ======================================================================
# Logica applicativa
# ======================================================================

def entries(db: dict) -> dict:
    return {k: v for k, v in db.items() if k not in (SALT_KEY, HEADER_KEY)}


def next_id(db: dict) -> str:
    ids = [int(k) for k in db.keys() if k not in (SALT_KEY, HEADER_KEY) and k.isdigit()]
    return str(max(ids) + 1) if ids else "1"


def add_password(db: dict, key: bytes) -> None:
    print("\nOk, aggiungiamo una nuova voce.")
    name = input("Nome del servizio: ").strip()
    if not name:
        print("Nome vuoto, annullato.")
        return
    username = input("Username (invio per lasciarlo vuoto): ").strip()
    pwd = getpass.getpass("Password da salvare: ")
    eid = next_id(db)
    db[eid] = {
        "name": name,
        "username": username,
        "pwd": encrypt_text(pwd, key),
    }
    save_db(db)
    print(f"Fatto, l'ho salvata come voce {eid}.")


def show_password(db: dict, key: bytes, choice: str) -> None:
    entry = db.get(choice)
    if not entry:
        print("Non trovo questa voce.")
        return
    try:
        pwd = decrypt_text(entry["pwd"], key)
    except (ValueError, KeyError, UnicodeDecodeError):
        print("Non riesco a decifrarla: password principale sbagliata o file corrotto.")
        return
    username = entry.get("username") or "(nessuno)"
    name = entry["name"]
    line_username = f"username: {username}"
    line_password = f"password: >>> {pwd} <<<"
    width = max(len(name), len(line_username), len(line_password), 20) + 2
    print("\n┌" + "─" * width + "┐")
    print(f"│ {name}".ljust(width + 1) + "│")
    print("├" + "─" * width + "┤")
    print(f"│ {line_username}".ljust(width + 1) + "│")
    print(f"│ {line_password}".ljust(width + 1) + "│")
    print("└" + "─" * width + "┘")


def print_manual() -> None:
    print("""
──────────────── MANUALE ────────────────
  <numero>          mostra la voce con quel numero
  0                 aggiunge una nuova password
  modifica <numero> modifica nome/username/password
  elimina <numero>  elimina una voce (chiede conferma)
  h                 mostra questo manuale
  bye               blocca e torna alla password
  bye bye           (alla richiesta password) chiude il programma
  enter             per lasciare vuoti campi come username o se non si vuole modificare
───────────────────────────────────────────""")


def modify_password(db: dict, key: bytes, cmd: str) -> None:
    parts = cmd.split(maxsplit=1)
    eid = parts[1].strip() if len(parts) > 1 else input("Quale numero vuoi modificare? ").strip()
    entry = db.get(eid)
    if not entry:
        print("Non trovo questa voce.")
        return
    print(f"\nStai modificando la voce {eid} ({entry['name']}).")
    new_name = input(f"Nome [{entry['name']}]: ").strip()
    new_username = input(f"Username [{entry.get('username') or '(nessuno)'}]: ").strip()
    new_pwd = getpass.getpass("Nuova password : ")

    if new_name:
        entry["name"] = new_name
    if new_username:
        entry["username"] = new_username
    if new_pwd:
        entry["pwd"] = encrypt_text(new_pwd, key)

    db[eid] = entry
    save_db(db)
    print("Aggiornata.")


def delete_password(db: dict, cmd: str) -> None:
    parts = cmd.split(maxsplit=1)
    eid = parts[1].strip() if len(parts) > 1 else input("Quale numero vuoi eliminare? ").strip()
    entry = db.get(eid)
    if not entry:
        print("Non trovo questa voce.")
        return
    conferma = input(f"Sicuro di voler eliminare \"{entry['name']}\"? (s/n): ").strip().lower()
    if conferma == "s":
        del db[eid]
        save_db(db)
        print("Eliminata.")
    else:
        print("Annullato.")


def assistant_loop(db: dict, key: bytes, header_line: str) -> None:
    """Ciclo del menu stile assistente. Ritorna quando l'utente scrive 'bye'."""
    while True:
        print(f"\n{header_line}")
        ent = entries(db)
        if not ent:
            print("Non hai ancora nessuna password salvata.")
        else:
            print("Ecco le tue voci salvate:")
            for eid in sorted(ent, key=int):
                print(f"  {eid}) {ent[eid]['name']}")
        cmd = input("\nTu: ").strip()
        low = cmd.lower()

        if low == "bye":
            print("\nOk, blocco l'accesso.")
            return
        elif low == "h":
            print_manual()
        elif cmd == "0":
            add_password(db, key)
        elif low.startswith("modifica"):
            modify_password(db, key, cmd)
        elif low.startswith("elimina"):
            delete_password(db, cmd)
        elif cmd.isdigit():
            show_password(db, key, cmd)
        else:
            print('\nNon ho capito, scrivi "h" per vedere i comandi disponibili.')


def main() -> None:
    print("Ciao! Sono il tuo assistente per le password.")
    print('Una volta dentro, scrivi "h" in qualsiasi momento per vedere il manuale dei comandi.')
    while True:
        db = load_db()
        first_run = SALT_KEY not in db
        salt = get_or_create_salt(db)

        master_password = getpass.getpass(
            "\nDimmi la password principale (scrivi 'bye bye' per uscire dal programma): "
        )
        if master_password.strip().lower() == "bye bye":
            print("\nA presto!")
            break

        key = derive_key(master_password, salt)

        if first_run:
            db[HEADER_KEY] = encrypt_text(HEADER_TEXT, key)
            header_line = HEADER_TEXT
        else:
            header_line = check_header(db, key)

        save_db(db)
        assistant_loop(db, key, header_line)


if __name__ == "__main__":
    main()
