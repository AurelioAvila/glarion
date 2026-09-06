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


## Report: chiarezza e impaginazione — 7 settembre 2026

- Report pubblico dimostrativo e report generati condividono lo stesso generatore: riepilogo, prime tre azioni collegate ai dettagli, conseguenza/intervento separati, evidenze visibili, osservazioni distinte dai controlli superati.
- Il campione usa dati dichiaratamente fittizi e conserva questa indicazione nel PDF. Metadati social e canonical conservati. Il pulsante stampa pubblico usa uno script locale compatibile con la CSP; per il documento servito in sandbox rimangono disponibili stampa del browser e Ctrl/Cmd+P.
- Impaginazione A4 verificata su tre pagine con Chrome 152: identità in un riquadro del margine inferiore, separato dai contenuti. Verificati anche nomi lunghi su desktop, telefono e PDF. La ripetizione nel margine richiede il supporto del browser ai CSS page margin boxes; non è stata verificata su altri browser.
- 23 test del report e 20 del frontend superati; controllo TypeScript superato. La prova contro testo ostile include la chiusura di style: i metadati nel margine vengono codificati integralmente come escape CSS.
- Revisione indipendente: grafica a schermo pronta; correzioni del margine PDF e dell'intestazione lunga valutate risolte, disposizione finale ship locally al perimetro esaminato.
- Landing: http://localhost:5186/ ; esempio aggiornato: http://localhost:5186/sample-report.html . Demo area clienti aggiornata con il nuovo generatore; nessuna pubblicazione eseguita.


## Rilascio pubblico — 7 settembre 2026 (Europe/Rome)

Approvazione utente: "ok va bene, procedi", dopo revisione delle anteprime.

- Pubblicata la revisione 087663c su Fly, release v63, da codex/restyle-security-20260906. Immagine immutabile: registry.fly.io/glarion-api@sha256:e98c7d2f6619010e045d449f294a14a3328647f9bf916e1b40fb47f9956c7ddb.
- Verifica completa locale superata: 292 test Rust, 20 frontend, controlli TypeScript, formattazione, Clippy, audit dipendenze; gate scansioni realmente eseguito su database dedicato. Dopo esaurimento disco, ripetuta compilazione seriale senza simboli debug, previa pulizia degli artefatti Cargo del solo progetto.
- Aggiornate app e worker; controlli Fly superati. Nessuna migrazione o modifica ai segreti richiesta. Versione precedente disponibile: v62, registry.fly.io/glarion-api:deployment-01M1NRWMDDH9SDXR95Z37CV7ZJ.
- Sul dominio pubblico: health 200; report, app, CSS, JavaScript, immagine e font 200 con SHA-256 identico agli artefatti locali. Landing nuova verificata nel browser; Cloudflare riscrive il solo contatto email e inserisce il relativo decoder, quindi il suo hash pubblico differisce dal file sorgente.
- Profile/scans/targets/billing senza autenticazione: 401 con Cache-Control no-store. Non eseguiti pagamenti, invii email o nuove scansioni reali in produzione.
- Branch salvato su GitHub; master resta alla base precedente. Rilascio diretto da CLI, senza attivare annunci Discord o pubblicazioni social. Prima di futuri rilasci da master, integrare il branch del restyle per evitare di sovrascriverlo.
- Anteprime pubbliche: https://glarion.app/ e https://glarion.app/sample-report.html . Il sito non è più limitato alle anteprime locali descritte nelle sezioni precedenti.
