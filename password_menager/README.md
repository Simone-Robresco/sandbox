Gestore password da CLI in stile "assistente" - AES-256 CBC puro Python,
nessuna dipendenza esterna (solo libreria standard).

- All'avvio chiede la password principale.
- Un piccolo "biglietto" (header) e' salvato cifrato nel json: se la
  password e' giusta si vede "==============", se e' sbagliata si vede
  la stringa cifrata grezza (nessun messaggio esplicito "password sbagliata").
- Scrivi "bye" per bloccare e tornare alla richiesta della password.
- Scrivi "bye bye" alla richiesta della password per chiudere il programma.
