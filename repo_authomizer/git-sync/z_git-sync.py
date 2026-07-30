import os
import json
import subprocess
import getpass
import shutil
import hashlib
import hmac
import secrets
import time

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
JSON_FILE = os.path.join(SCRIPT_DIR, "repos.json")
AUTH_FILE = os.path.join(SCRIPT_DIR, "auth.json")


def run(cmd, cwd=None):
    print(f"\n> {cmd}")
    result = subprocess.run(
        cmd, shell=True, text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        cwd=cwd
    )
    print(result.stdout)
    return result.returncode == 0


def trova_gh():
    """Cerca l'eseguibile di GitHub CLI: prima nel PATH, poi nei percorsi
    tipici di installazione (utile se il PATH non è ancora aggiornato)."""
    trovato = shutil.which("gh")
    if trovato:
        return trovato

    candidati = [
        os.path.expandvars(r"%LOCALAPPDATA%\Microsoft\WinGet\Links\gh.exe"),
        r"C:\Program Files\GitHub CLI\gh.exe",
        os.path.expandvars(r"%LOCALAPPDATA%\Programs\GitHub CLI\gh.exe"),
    ]
    for c in candidati:
        if os.path.exists(c):
            return c
    return None


def load_repos():
    if not os.path.exists(JSON_FILE):
        with open(JSON_FILE, "w") as f:
            json.dump({}, f, indent=4)
        return {}
    with open(JSON_FILE, "r") as f:
        return json.load(f)


def save_repos(repos):
    with open(JSON_FILE, "w") as f:
        json.dump(repos, f, indent=4)


def crea_repo_su_github(name, path, gh_path):
    """Inizializza la cartella locale, crea il repo su GitHub e collega il remote.
    Ritorna l'URL del repo, oppure None se la parte GitHub è fallita
    (la cartella e il git init locale restano comunque fatti)."""

    visibilita = input("Privata o pubblica? (priv/pub) [priv]: ").strip().lower()
    flag_vis = "--public" if visibilita == "pub" else "--private"

    if not os.path.exists(os.path.join(path, ".git")):
        run("git init", path)
        run("git branch -M main", path)

    # gh ha bisogno di almeno un commit prima di poter pushare
    ha_commit = run("git rev-parse HEAD", path)
    if not ha_commit:
        readme_path = os.path.join(path, "README.md")
        if not os.path.exists(readme_path):
            with open(readme_path, "w") as f:
                f.write(f"# {name}\n")
        run("git add -A", path)
        run('git commit -m "Initial commit"', path)

    gh_cmd = f'"{gh_path}"' if " " in gh_path else gh_path
    ok = run(f'{gh_cmd} repo create "{name}" {flag_vis} --source="." --remote=origin --push', path)
    if not ok:
        print("\nCreazione su GitHub fallita. Controlla l'output sopra "
              "(potresti dover fare 'gh auth login' oppure il nome è già in uso).")
        return None

    result = subprocess.run(
        "git remote get-url origin", shell=True, text=True,
        capture_output=True, cwd=path
    )
    url = result.stdout.strip()
    print(f"\nRepo creato su GitHub: {url}")
    return url


def add_repo(repos):
    print("\n--- AGGIUNGI REPO ---")
    name = input("Nome repo: ").strip()

    crea_online = input("Creare anche il repository su GitHub? (s/n): ").strip().lower() == "s"

    url = None
    if crea_online:
        base_path = input("Cartella dentro cui creare il progetto: ").strip()
        # la cartella finale del progetto è base_path/name, così il .git
        # non finisce direttamente nella cartella che hai indicato
        path = os.path.join(base_path, name)

        # la cartella locale la creiamo SEMPRE, anche se gh non si trova
        try:
            os.makedirs(path, exist_ok=True)
        except OSError as e:
            print(f"\nERRORE: impossibile creare la cartella '{path}': {e}")
            return

        gh_path = trova_gh()
        if not gh_path:
            print("\nATTENZIONE: GitHub CLI ('gh') non trovato (né nel PATH né nei percorsi "
                  "di installazione standard).")
            print("La cartella locale è stata creata, ma il repo su GitHub NON è stato creato.")
            print("Riavvia il terminale dopo l'installazione di gh, oppure crea il repo a mano "
                  "su github.com e poi aggiungi il remote con:")
            print(f'  git remote add origin <url-del-repo>   (dentro "{path}")')
        else:
            url = crea_repo_su_github(name, path, gh_path)

    else:
        # repo già esistente su GitHub: qui il percorso è la cartella finale esatta
        path = input("Percorso locale: ").strip()
        url = input("URL git: ").strip()

    new_id = str(max([int(k) for k in repos.keys()] + [0]) + 1)
    repos[new_id] = {
        "name": name,
        "path": path,
        "url": url or ""
    }
    save_repos(repos)
    print("\nRepo aggiunta!")


def ensure_repo(repo):
    path = repo["path"]

    if not os.path.exists(path):
        print("\nCartella non trovata → CLONE automatico")
        parent = os.path.dirname(path)
        if parent:  # evita os.makedirs("") che crasha
            try:
                os.makedirs(parent, exist_ok=True)
            except OSError as e:
                print(f"\nERRORE: impossibile creare la cartella '{parent}'")
                print(f"Dettaglio: {e}")
                print("Controlla che il percorso in repos.json sia corretto "
                      "e che tu abbia i permessi necessari.")
                return False
        ok = run(f'git clone "{repo["url"]}" "{path}"')
        if not ok:
            print("Clone fallito, controlla URL/permessi.")
            return False
        return True

    if not os.path.exists(os.path.join(path, ".git")):
        print("\nERRORE: cartella esiste ma non è una repo git")
        return False

    return True


def get_current_branch(path):
    result = subprocess.run(
        "git rev-parse --abbrev-ref HEAD",
        shell=True, text=True, capture_output=True, cwd=path
    )
    branch = result.stdout.strip()
    return branch if branch else "main"


def gestisci_repo(repo):
    if not ensure_repo(repo):
        return

    print("\n0) Torna al menu")
    print("1) PULL")
    print("2) PUSH")
    azione = input("\nScelta: ").strip()

    if azione == "1":
        print(f"\n--- PULL {repo['name']} ---")
        branch = get_current_branch(repo["path"])
        if not run("git fetch", repo["path"]):
            print("Fetch fallito.")
        elif not run(f"git reset --hard origin/{branch}", repo["path"]):
            print("Reset fallito.")
        run("git log -1 --oneline", repo["path"])

    elif azione == "2":
        print(f"\n--- PUSH {repo['name']} ---")
        run("git status --short", repo["path"])
        run("git add -A", repo["path"])
        # se non c'è nulla da committare, git commit fallisce: non è un errore bloccante
        run('git commit -m "update"', repo["path"])
        branch = get_current_branch(repo["path"])
        if not run("git push", repo["path"]):
            print("Push normale fallito, provo a impostare l'upstream...")
            if not run(f"git push --set-upstream origin {branch}", repo["path"]):
                print("Push fallito (controlla eventuali conflitti/permessi).")

    elif azione == "0":
        return
    else:
        print("Scelta non valida")


def menu():
    while True:
        repos = load_repos()
        print("\n=== REPO ===")
        print("0) + Aggiungi nuova repo")
        for key, repo in repos.items():
            print(f"{key}) {repo['name']}")
        print("q) Esci")

        scelta = input("\nSeleziona: ").strip()

        if scelta.lower() == "q":
            print("Uscita.")
            break

        if scelta == "0":
            add_repo(repos)
            continue

        if scelta not in repos:
            print("Scelta non valida")
            continue

        gestisci_repo(repos[scelta])


def _deriva_hash(password, salt, iterazioni):
    return hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterazioni)


def _imposta_password():
    print("\n--- PRIMO AVVIO: imposta una password ---")
    while True:
        pwd1 = getpass.getpass("Nuova password: ")
        if len(pwd1) < 4:
            print("Usa almeno 6 caratteri.")
            continue
        pwd2 = getpass.getpass("Conferma password: ")
        if pwd1 != pwd2:
            print("Le due password non coincidono, riprova.")
            continue
        break

    salt = secrets.token_bytes(16)
    iterazioni = 200_000
    hash_pwd = _deriva_hash(pwd1, salt, iterazioni)

    with open(AUTH_FILE, "w") as f:
        json.dump({
            "salt": salt.hex(),
            "hash": hash_pwd.hex(),
            "iterazioni": iterazioni
        }, f, indent=4)

    print("Password impostata correttamente.\n")


def check_password():
    if not os.path.exists(AUTH_FILE):
        _imposta_password()
        return True

    with open(AUTH_FILE, "r") as f:
        dati = json.load(f)
    salt = bytes.fromhex(dati["salt"])
    iterazioni = dati["iterazioni"]
    hash_atteso = bytes.fromhex(dati["hash"])

    max_tentativi = 5
    for tentativo in range(max_tentativi):
        pwd = getpass.getpass("pwd: ")
        hash_inserito = _deriva_hash(pwd, salt, iterazioni)
        if hmac.compare_digest(hash_inserito, hash_atteso):
            return True

        rimanenti = max_tentativi - tentativo - 1
        print(f"pwd sbagliata ({rimanenti} tentativi rimasti)")
        if rimanenti > 0:
            time.sleep(1.5)  # rallenta eventuali tentativi ripetuti

    print("Troppi tentativi falliti.")
    return False


if __name__ == "__main__":
    if check_password():
        menu()