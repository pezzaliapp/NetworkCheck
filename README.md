# NetworkCheck

NetworkCheck è una **web app / PWA educativa e diagnostica** pensata per utenti
non tecnici. Aiuta a capire cosa è esposto nella propria rete locale e sul proprio
computer, **senza eseguire alcuna scansione dal browser**.

L'app ti guida con i comandi corretti per **macOS, Windows e Linux**, ti spiega
cosa fa ciascun comando e ti aiuta a interpretare l'output che **incolli** tu.
Tutta l'analisi avviene **lato client**: nessun dato lascia il dispositivo.

## Caratteristiche

- **Zero dipendenze**: solo HTML, CSS e JavaScript vanilla (ES modules).
- **Nessuna chiamata di rete a runtime**: niente CDN, font esterni, analytics o backend.
- **Privacy-first**: vengono salvate localmente solo la lingua scelta e il consenso
  al disclaimer; i contenuti incollati non vengono mai memorizzati.
- **PWA installabile** e funzionante offline dopo il primo caricamento.
- **Bilingue** italiano / inglese con toggle (default IT, fallback EN).
- **Accessibile** (WCAG 2.1 AA): navigazione da tastiera, focus visibile,
  skip-link, ruoli ARIA, rispetto di `prefers-reduced-motion`.

## Sezioni diagnostiche

1. **Servizi esposti** — comandi per elencare le porte in ascolto sul tuo computer
   (`lsof`, `netstat`, `ss`), tabella di riferimento delle porte più comuni e
   interprete dell'output che distingue i servizi locali da quelli potenzialmente
   raggiungibili dalla rete.
2. **Dispositivi nella rete** — generatore di comando: inserisci il tuo IP locale e
   l'app calcola la subnet `/24` e prepara il comando `nmap -sn` pronto da copiare;
   interprete del risultato per contare gli host trovati.
3. **Stato del firewall** — comandi per verificare se il firewall di sistema è attivo
   su macOS, Windows e Linux, con interpretazione dell'output.

## Onestà (anti security-theater)

NetworkCheck **non** fa promesse di sicurezza e **non** sostituisce un audit
professionale. L'interprete dell'output è euristico e usa sempre linguaggio
probabilistico ("possibile", "probabile", "da verificare"): non emette mai verdetti
del tipo "sei al sicuro".

## Uso responsabile

Usa i comandi di scansione (come `nmap`) **solo** su reti e dispositivi tuoi o per i
quali hai esplicita autorizzazione. Scansionare reti altrui può costituire reato.

## Avvio in locale

Essendo basata su ES modules e service worker, va servita via HTTP (non `file://`):

```
python3 -m http.server 8765
```

Poi apri `http://localhost:8765`. Pubblicabile così com'è su GitHub Pages (tutti i
percorsi sono relativi; è incluso `.nojekyll`).

## Struttura

```
index.html
css/style.css
js/app.js            entrypoint, orchestrazione UI
js/parser.js         interprete output, modulo puro e testabile
js/i18n.js           stringhe IT/EN
manifest.webmanifest
sw.js
icons/
```

## Licenza

[MIT](./LICENSE) — Alessandro Pezzali / pezzaliAPP.

---

## NetworkCheck (English summary)

NetworkCheck is an **educational, diagnostic web app / PWA** for non-technical
users. It helps you understand what is exposed on your local network and computer
**without performing any scan from the browser**.

It guides you with the correct commands for **macOS, Windows and Linux**, explains
what each command does and helps you interpret the output **you paste** yourself.
All analysis happens **client-side**: no data ever leaves your device.

**Highlights**

- Zero dependencies: plain HTML, CSS and vanilla JavaScript (ES modules).
- No outgoing network calls at runtime (no CDN, external fonts, analytics or backend).
- Privacy-first: only your language choice and disclaimer consent are stored locally;
  pasted content is never saved.
- Installable PWA, works offline after the first load.
- Bilingual Italian / English (default IT, fallback EN).
- Accessible (WCAG 2.1 AA): keyboard navigation, visible focus, skip-link, ARIA roles,
  `prefers-reduced-motion` support.

**Diagnostic sections**: exposed services (listening ports + reference table +
heuristic interpreter), devices on the network (nmap `/24` command builder from your
local IP), firewall status.

**Honesty**: NetworkCheck makes no security promises and does not replace a
professional audit. The interpreter is heuristic and always uses probabilistic
language — it never says "you are safe".

**Responsible use**: run scanning commands (such as `nmap`) only on networks and
devices you own or are explicitly authorized to test. Scanning other people's
networks may be a crime.

**License**: [MIT](./LICENSE) — Alessandro Pezzali / pezzaliAPP.
