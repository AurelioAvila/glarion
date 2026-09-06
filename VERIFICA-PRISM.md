# Restyle Prism — verifica locale

## Consegna

Direzione grafica 6 scelta dall’utente e successivamente estesa all’area clienti e alle altre pagine.

- Homepage e ingresso account: perla, lilla, corallo, Manrope locale e anello ottico.
- Area clienti: siti, dettaglio, scansioni, piano e impostazioni; navigazione mobile accessibile.
- Guide, privacy, termini e report dimostrativo coerenti. Testi legali invariati.
- Report generati: palette coerente, impaginazione adattabile e stampa, senza nuove richieste esterne.

## Migliorie funzionali

- Le richieste dell’area clienti usano la stessa origine anche nelle anteprime locali, eliminando il rinvio implicito alla porta 8080.
- Il collegamento per saltare al contenuto sposta il focus senza cambiare schermata.
- Navigazione attiva e apertura del modulo per aggiungere un sito hanno stati accessibili espliciti.
- Errori annunciati alle tecnologie assistive; lunghezza minima della nuova password allineata alle istruzioni.
- Onboarding corretto: verifica via DNS o file, con validità di 30 giorni.
- Rimosso il titolo duplicato nelle impostazioni.

## Evidenze

- Build e controllo TypeScript superati.
- 20 test frontend superati, inclusa la regressione sull’origine delle richieste e i token dei fogli di stile collegati.
- 21 test del generatore di report superati, inclusi escaping e comportamento di stampa.
- Accesso con credenziali volutamente inesistenti: risposta corretta dal servizio locale, senza richiesta alla porta 8080.
- Navigazione da tastiera: focus sul contenuto, percorso corrente conservato.
- Modulo aggiunta sito e collegamenti verificati; nessuno sconfinamento orizzontale nelle viste mobile controllate.
- Pagine e nuovi asset serviti con risposta HTTP 200.
- Revisione indipendente: `ship`, limitata alle aree visibili delle nove catture consegnate. Il rilevatore automatico era limitato al controllo testuale e non certifica il contrasto calcolato dal browser.

## Anteprime e limiti

Applicazione locale: http://localhost:5186/app/#/signin

Demo area clienti: http://127.0.0.1:5192/app/#/targets

La demo è separata, usa dati fittizi esplicitamente etichettati e rifiuta modifiche, pagamenti e scansioni. Il report scaricabile nella demo è un esempio indipendente dai conteggi dell’elenco. Il server dimostrativo è in `.preview`, escluso dal pacchetto di produzione.

In questo passaggio non sono stati verificati creazione effettiva di account, invio email, pagamenti o scansioni reali. Non è stata pubblicata alcuna modifica. Le correzioni di sicurezza precedenti sono conservate; questo restyle non equivale a una nuova verifica completa della sicurezza.
