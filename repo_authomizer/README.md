# zart 🚀

Piccolo tool da terminale per gestire il pull/push di più repository Git da un unico menu, con creazione automatica dei repo su GitHub e accesso protetto da password.

Si chiama **zart** perché nella cartella `codici` compare in cima alla lista (ordinamento alfabetico) e quindi lo trovo subito senza doverlo cercare tra tutti gli altri progetti.

---

## Struttura delle cartelle

```
codici/
├── zart.bat                → lanciatore rapido (doppio click e parte tutto)
└── git-sync/
    ├── z_git-sync.py        → script principale
    ├── logo.txt             → logo ASCII mostrato all'avvio
    ├── repos.json            → generato automaticamente, lista dei repo gestiti
    └── auth.json             → generato automaticamente, password hashata
```

`zart.bat` si aspetta di trovarsi **un livello sopra** la cartella `git-sync`. Se sposti qualcosa, ricordati che i percorsi in `zart.bat` sono relativi alla sua posizione (`%~dp0`).

---

## Cosa fa ogni file

### `z_git-sync.py`
Il cuore del progetto. Un menu testuale che permette di:

- **Gestire più repo** da un unico posto, salvate in `repos.json` (nome, percorso locale, URL).
- **Clonare in automatico** una repo se la cartella locale non esiste ancora.
- **Creare un nuovo repo direttamente su GitHub** (senza aprire GitHub Desktop): crea la cartella locale, fa `git init`, un commit iniziale con un README se serve, crea il repo su GitHub tramite **GitHub CLI (`gh`)** con la visibilità scelta (privato/pubblico), collega il remote e fa il primo push, tutto in automatico.
- **PULL**: fa `git fetch` + `git reset --hard` sul branch corrente (rileva da solo se è `main`, `master` o altro).
- **PUSH**: aggiunge, committa e pusha; se manca l'upstream (tipico su un repo nuovo) lo imposta da solo con `--set-upstream` invece di darti solo l'errore.
- **Accesso protetto da password**, gestito in modo sicuro (vedi sotto).

### `auth.json` *(generato automaticamente)*
Al primo avvio, se questo file non esiste, lo script ti chiede di **impostare una password** (con conferma). Non viene mai salvata in chiaro: viene derivato un hash **PBKDF2-SHA256 con salt casuale a 200.000 iterazioni**, e solo salt + hash finiscono in questo file. Ai login successivi il confronto avviene a tempo costante (`hmac.compare_digest`), con un massimo di 5 tentativi e una pausa tra uno sbagliato e l'altro per scoraggiare bruteforce.

**Per cambiare password:** cancella `auth.json` e rilancia lo script — ripartirà il setup come al primo avvio.

### `repos.json` *(generato automaticamente)*
Elenco dei repository gestiti, con id numerico, nome, percorso locale e URL remoto. Viene creato vuoto al primissimo avvio e aggiornato ogni volta che aggiungi una repo dal menu.

### `logo.txt`
Il logo ASCII mostrato all'avvio da `zart.bat`.

### `zart.bat`
Lanciatore: stampa il logo, entra nella cartella `git-sync` e avvia `python z_git-sync.py`.

**Nota/TODO:** il `color 0B` dovrebbe colorare il testo di azzurro ma il titolo non viene mostrato colorato come dovrebbe — da sistemare. Se vuoi possiamo rivederlo insieme più avanti.

---

## Setup da zero

### 1. Software da installare

| Software | A cosa serve | Comando |
|---|---|---|
| **Python 3** | esegue lo script | scarica da [python.org](https://python.org) — spunta "Add python.exe to PATH" durante l'installazione |
| **Git** | comandi git usati dallo script | scarica da [git-scm.com](https://git-scm.com) |
| **GitHub CLI (`gh`)** | creazione automatica dei repo su GitHub | `winget install --id GitHub.cli` |

Dopo aver installato `gh`, **chiudi e riapri il terminale** (il PATH si aggiorna solo nelle nuove sessioni), poi autenticati una volta sola:

```
gh auth login
```

Scelte consigliate durante la procedura:
- Account: `GitHub.com`
- Protocollo: `HTTPS`
- Autenticare Git con le credenziali GitHub: `Yes`
- Metodo: `Login with a web browser` → copia il codice mostrato, premi invio, incolla il codice nel browser e clicca **Authorize**

Verifica che sia andato tutto a buon fine con `gh --version` e `gh auth status`.

Verifica anche che Git sappia chi sei (serve per i commit):
```
git config --global user.name "Il tuo nome"
git config --global user.email "tua-email@esempio.com"
```

### 2. Posizionare i file

Crea la struttura di cartelle mostrata sopra: `zart.bat` nella cartella `codici`, e dentro `git-sync/` metti `z_git-sync.py` e `logo.txt`. `repos.json` e `auth.json` **non li crei tu**: li genera lo script da solo al primo utilizzo, nella stessa cartella dove si trova `z_git-sync.py` (indipendentemente da dove lanci lo script).

### 3. Primo avvio

Doppio click su `zart.bat` (oppure, dentro la cartella `git-sync`, `python z_git-sync.py`):

1. Ti verrà chiesto di **impostare una password** → scrivila e confermala.
2. Si apre il menu: scegli `0` per aggiungere la tua prima repo.
3. Se scegli di crearla anche su GitHub, ti verrà chiesta la cartella base dove creare il progetto e se privata o pubblica — al resto pensa lo script.

---

## Attenzione: prima di pushare *questo* progetto su GitHub

Se `zart` stesso finisce in un repository, **non committare mai** `auth.json` e `repos.json`: il primo contiene l'hash della tua password, il secondo i percorsi/URL delle tue repo locali. Aggiungi un `.gitignore` con:

```
auth.json
repos.json
```