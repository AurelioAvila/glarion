# Glarion — verifica e correzioni del 6 settembre 2026

Stato: modifiche locali su codex/restyle-security-20260906, basate sul commit
372ea89. Non distribuite in produzione. Revisione di codice, test locali e lettura
delle risposte pubbliche del sito; nessun test di carico o attacco su produzione.
Questa verifica non certifica immunità a tutti gli attacchi.

## Correzioni implementate

| Riscontro | Effetto prima della correzione | Correzione e prova |
|---|---|---|
| Filtro delle destinazioni incompleto | Alcuni indirizzi speciali superavano is_public_ip: per esempio 0.1.2.3, IPv6 di traduzione/transizione e spazio riservato. Il reale instradamento dipende dall'infrastruttura; non è stato dimostrato un accesso a sistemi interni. | Rifiuto dell'intero 0/8, trattamento coerente degli IPv4 mapped e politica conservativa IPv6: global unicast nativo con esclusioni esplicite. Test sui limiti e sugli indirizzi pubblici validi. |
| CSP dei report sovrascritta | Il wrapper delle pagine sostituiva la policy sandbox dei report con quella più permissiva del dashboard. Non è stata trovata una vulnerabilità XSS sfruttabile; veniva meno una difesa aggiuntiva. | Applicazione della policy generale solo in assenza di una policy specifica. Test della risposta attraverso il wrapper. |
| Risposte API senza divieto esplicito di cache | Risultati, profili e risposte di sessione non avevano una direttiva generale che ne vietasse la memorizzazione. | Cache-Control: no-store sul router API, verificato anche sulle risposte di autenticazione negata. Le risorse statiche mantengono la rivalidazione. |

La politica IPv6 è volutamente restrittiva: indirizzi di protocollo speciali,
traduzione e tunnel sono esclusi anche quando alcuni hanno usi legittimi.
La funzione non è una libreria universale di classificazione IANA, ma una policy
per destinazioni di siti web. Riferimento:
[registro IANA](https://www.iana.org/assignments/iana-ipv6-special-registry/).

## Evidenza di validazione

- 290 test Rust passati su database locale dedicato, inclusi i 15 test del gate
  delle scansioni, recupero/cambio password, cambio email e cancellazione account.
- Clippy su tutti i target senza warning; formattazione Rust verificata.
- 19 test frontend passati, controllo TypeScript e compilazione riusciti.
- cargo audit e npm audit: nessuna vulnerabilità nota segnalata alla data del controllo.
- Ricerca automatica di segreti: nessun segreto di produzione confermato. Due
  falsi positivi verificati: URL del database usa-e-getta in CI e integrità SHA-512
  di un pacchetto nel lockfile. Il controllo non equivale a una revisione completa
  della cronologia Git o dei segreti configurati nei servizi.
- Controllo pubblico eseguito tramite l'anteprima locale su glarion.app: risultati
  mostrati, limiti visibili, nessun account o invio email necessario.
- JSON-LD preservato byte per byte rispetto alla base: hash autorizzato dalla CSP
  ancora corrispondente. Nessuno script, tracker o font remoto aggiunto.

## Confini e minacce considerate

I modelli STRIDE automatici sono checklist generiche, non vulnerabilità provate.
I punteggi non sono CVSS del prodotto. Responsabile delle mitigazioni: manutentore
Glarion; le verifiche operative restano da completare prima di dichiararle attive.

| Confine | Minacce considerate | Difese presenti / stato |
|---|---|---|
| Browser → autenticazione/API | Furto credenziali, contraffazione token, CSRF, brute force, escalation | Argon2, HMAC con algoritmo fisso, revoca token_version, cookie HttpOnly/Secure, controllo CSRF e rate limit condivisi. MFA/passkey non implementati nel progetto verificato. |
| API → database | Iniezione, accesso ai dati altrui, alterazione audit | Query parametrizzate e filtri per proprietario verificati nei flussi esaminati; autorizzazione e job scritti insieme. Privilegi del DB di produzione e protezione dei backup non ispezionati. |
| Worker → siti/DNS | SSRF, rebinding, abuso del motore e indisponibilità | Verifica proprietà ripetuta, indirizzi validati, pinning delle richieste proprie, restrizione rete locale in Nuclei, rate e timeout. Serve conferma delle regole egress operative del worker. |
| Finding → report/browser | XSS, esfiltrazione, memorizzazione di dati | Escaping, report come allegato, CSP specifica preservata, no-store. |
| Proxy → API | Falsificazione IP, aggiramento o collisione dei rate limit, DDoS | Fly-Client-IP considerato solo dietro proxy fidato; Cloudflare davanti al sito. Verificare il comportamento della catena Cloudflare/Fly con più IP legittimi e l'accesso diretto all'origine. Non fidarsi di CF-Connecting-IP senza provare il proxy di provenienza. |
| Operatori → infrastruttura e fornitori | Furto account/chiavi, modifica deployment, perdita dati | MFA degli account cloud, rotazione chiavi, privilegi minimi, alert e ripristino backup sono controlli operativi non verificati in questa sessione. |

Le checklist hanno due minacce generiche con DREAD ≥7: furto credenziali (8.2)
e impersonificazione API (7.2). Per la prima il manutentore deve pianificare
MFA/passkey e verificare MFA dei servizi cloud. La seconda si traduce qui in
protezione del segreto di firma e delle sessioni: nessuna API key utente è stata
trovata come meccanismo di accesso del prodotto. La firma, i cookie e la revoca
sono coperti dal codice; la custodia operativa delle chiavi resta da verificare.

## Prossime priorità operative

1. Distribuire le correzioni validate e verificare le risposte reali dopo il rilascio.
2. Verificare MFA dei servizi, backup con prova di ripristino, alert su errori,
   abusi e dipendenze, accesso all'origine e confine di rete del worker.
3. Pianificare MFA/passkey per gli utenti e una revisione indipendente dei flussi
   più sensibili; verificare limiti di risorse e hashing sotto carico in staging.

Queste attività non sono dichiarate completate. Un WAF o un test automatico
non sostituiscono autenticazione, isolamento, aggiornamenti e recuperabilità.
Riferimento: [OWASP REST Security](https://cheatsheetseries.owasp.org/cheatsheets/REST_Security_Cheat_Sheet.html).


## Aggiornamento distribuzione — 7 settembre 2026

Le correzioni descritte sono ora distribuite con la release Fly v63 (revisione 087663c). Verificati sul dominio pubblico rifiuto degli accessi non autenticati e Cache-Control no-store. La CSP specifica dei report e il filtro delle destinazioni restano coperti dai test locali; non sono stati eseguiti attacchi o scansioni nuove in produzione. I controlli operativi elencati sopra non sono dichiarati completati. Dettagli e rollback in VERIFICA-PRISM.md.
