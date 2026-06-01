/**
 * i18n.js — Stringhe dell'interfaccia in italiano e inglese.
 *
 * Default: IT. Fallback: EN. Le chiavi sono piatte e condivise tra le due lingue.
 * I valori possono contenere segnaposto `{nome}` interpolati a runtime.
 *
 * @module i18n
 */

/**
 * Dizionario delle stringhe per lingua.
 * @type {{it: Object<string,string>, en: Object<string,string>}}
 */
export const I18N = {
  it: {
    'app.title': 'NetworkCheck',
    'app.tagline': 'Capisci cosa è esposto nella tua rete e sul tuo computer.',
    'app.skip': 'Vai al contenuto principale',
    'lang.toggle': 'English',
    'lang.aria': 'Cambia lingua in inglese',

    'intro.title': 'Come funziona',
    'intro.p1':
      'NetworkCheck non esegue scansioni dal browser e non invia nulla in rete. Tutta l’analisi avviene sul tuo dispositivo.',
    'intro.p2':
      'Ti guida con i comandi giusti per macOS, Windows e Linux. Esegui il comando nel terminale, poi incolla qui l’output: l’app prova a spiegartelo in modo semplice.',
    'intro.note':
      'Le interpretazioni sono indicative e probabilistiche. NetworkCheck non sostituisce un audit di sicurezza professionale.',

    // Sezione: Servizi esposti
    'svc.title': 'Servizi esposti',
    'svc.desc':
      'Mostra i programmi del tuo computer in ascolto sulla rete. Un servizio in ascolto su 0.0.0.0 o * è potenzialmente raggiungibile dagli altri dispositivi; uno su 127.0.0.1 resta locale.',
    'svc.cmdMac': 'macOS',
    'svc.cmdWin': 'Windows',
    'svc.cmdLinux': 'Linux',
    'svc.altTitle': 'Comandi alternativi',
    'svc.altMac': 'macOS — mostra i tuoi indirizzi IP locali:',
    'svc.altLinuxIp': 'Linux — mostra i tuoi indirizzi IP locali:',
    'svc.altLinuxSs': 'Linux — porte in ascolto con processo:',
    'svc.winPidTitle': 'Windows — dal PID al programma',
    'svc.winPid':
      'L’ultima colonna di netstat è il PID. Apri Gestione attività (Ctrl+Maiusc+Esc), scheda Dettagli, e cerca quel PID nella colonna PID per scoprire il programma. Se la colonna PID non è visibile, fai clic destro sull’intestazione → Seleziona colonne → PID.',
    'svc.tableTitle': 'Porte di riferimento',
    'svc.thPort': 'Porta',
    'svc.thService': 'Servizio',
    'svc.thNote': 'Nota',
    'svc.pasteLabel': 'Incolla qui l’output del comando',
    'svc.placeholder': 'Incolla l’output del terminale…',
    'svc.analyze': 'Interpreta l’output',
    'svc.clear': 'Pulisci',

    // Sezione: Dispositivi nella rete
    'net.title': 'Dispositivi nella rete',
    'net.desc':
      'Elenca i dispositivi attivi sulla tua rete locale. Usa nmap solo su reti e dispositivi tuoi o autorizzati.',
    'net.builderTitle': 'Generatore di comando',
    'net.builderDesc':
      'Inserisci il tuo IP locale (lo trovi con i comandi alternativi qui sopra): l’app calcola la subnet /24 e prepara il comando nmap.',
    'net.ipLabel': 'Il tuo IP locale',
    'net.ipPlaceholder': 'es. 192.168.1.42',
    'net.build': 'Genera comando',
    'net.builtLabel': 'Comando generato',
    'net.pasteLabel': 'Incolla qui l’output di nmap',
    'net.placeholder': 'Incolla l’output di nmap…',

    // Sezione: Firewall
    'fw.title': 'Stato del firewall',
    'fw.desc':
      'Verifica se il firewall del sistema operativo è attivo. Un firewall attivo riduce la superficie raggiungibile, ma non è una garanzia assoluta.',
    'fw.cmdMac': 'macOS',
    'fw.cmdWin': 'Windows',
    'fw.cmdLinux': 'Linux (ufw)',
    'fw.pasteLabel': 'Incolla qui l’output del comando',
    'fw.placeholder': 'Incolla l’output del terminale…',

    // Azioni comuni
    'copy.label': 'Copia',
    'copy.done': 'Copiato!',
    'copy.fail': 'Copia non riuscita',
    'results.title': 'Osservazioni',

    // Descrizioni porte
    'port.21': 'Trasferimento file non cifrato. Spesso sconsigliato.',
    'port.22': 'Accesso remoto cifrato. Limita l’accesso se non serve.',
    'port.23': 'Accesso remoto NON cifrato. Da evitare.',
    'port.53': 'Risoluzione nomi (DNS).',
    'port.80': 'Sito o servizio web non cifrato.',
    'port.139': 'Condivisione file legacy (NetBIOS).',
    'port.443': 'Sito o servizio web cifrato.',
    'port.445': 'Condivisione file Windows (SMB). Sensibile se esposta.',
    'port.3389': 'Desktop remoto Windows (RDP). Sensibile se esposto.',
    'port.5000': 'Server di sviluppo locale comune.',
    'port.8080': 'Servizio web alternativo, spesso di sviluppo.',
    'port.8765': 'Tipico di un server Python avviato a mano.',

    // Findings
    'finding.exposed.title': 'Servizio potenzialmente esposto: {service} (porta {port}/{proto})',
    'finding.exposed.detail':
      'Risulta in ascolto su {address}, quindi potrebbe essere raggiungibile da altri dispositivi della rete. Verifica se ti serve davvero che sia accessibile.',
    'finding.local.title': 'Servizio locale: {service} (porta {port}/{proto})',
    'finding.local.detail':
      'In ascolto solo in locale (127.0.0.1): probabilmente non è raggiungibile dalla rete.',
    'finding.hosts.title': 'Rilevati {count} dispositivi sulla rete',
    'finding.hosts.detail':
      'nmap ha trovato {count} host attivi. Controlla se li riconosci tutti; un dispositivo sconosciuto andrebbe verificato.',
    'finding.open.title': 'Porta aperta: {service} (porta {port}/{proto})',
    'finding.open.detail':
      'Il dispositivo risponde su questa porta. Valuta se il servizio dovrebbe essere accessibile.',
    'finding.fwOn.title': 'Firewall probabilmente attivo',
    'finding.fwOn.detail':
      'L’output indica un firewall attivo. È un buon segnale, ma non una garanzia assoluta.',
    'finding.fwOff.title': 'Firewall probabilmente disattivato',
    'finding.fwOff.detail':
      'L’output indica un firewall non attivo. Valuta se attivarlo, soprattutto su reti non fidate.',
    'finding.none.title': 'Nessun pattern riconosciuto',
    'finding.none.detail':
      'Non sono stati riconosciuti elementi noti nell’output. Assicurati di aver incollato il risultato completo di uno dei comandi suggeriti.',

    // Errori analisi
    'analyze.empty': 'Incolla prima un output da interpretare.',
    'analyze.tooBig': 'Testo troppo lungo (oltre 100 KB). Incolla solo la parte rilevante.',
    'builder.invalid': 'IP non valido. Usa un formato come 192.168.1.42.',

    // Disclaimer / consenso
    'disc.title': 'Prima di iniziare',
    'disc.p1':
      'NetworkCheck è uno strumento personale, educativo e diagnostico. Non esegue scansioni: ti guida e interpreta ciò che incolli.',
    'disc.li1':
      'Usa i comandi di scansione (come nmap) solo su reti e dispositivi tuoi o per i quali hai esplicita autorizzazione. Scansionare reti altrui può costituire reato.',
    'disc.li2':
      'Nessun dato viene raccolto, inviato o memorizzato esternamente. Tutto resta sul tuo dispositivo (in linea con il GDPR).',
    'disc.li3':
      'Le interpretazioni sono euristiche e probabilistiche: non sostituiscono un audit di sicurezza.',
    'disc.checkbox': 'Ho letto e accetto',
    'disc.enter': 'Entra',
    'disc.link': 'Disclaimer',

    // Footer
    'footer.privacy':
      'Nessun dato lascia il tuo dispositivo. Vengono salvate solo la lingua e il consenso.',
    'footer.clear': 'Cancella tutto',
    'footer.cleared': 'Dati locali cancellati.',
    'footer.author': 'Alessandro Pezzali / pezzaliAPP',
    'footer.offline': 'Funziona offline dopo il primo caricamento.',
  },

  en: {
    'app.title': 'NetworkCheck',
    'app.tagline': 'Understand what is exposed on your network and computer.',
    'app.skip': 'Skip to main content',
    'lang.toggle': 'Italiano',
    'lang.aria': 'Switch language to Italian',

    'intro.title': 'How it works',
    'intro.p1':
      'NetworkCheck does not scan from the browser and sends nothing over the network. All analysis happens on your device.',
    'intro.p2':
      'It guides you with the right commands for macOS, Windows and Linux. Run the command in your terminal, then paste the output here: the app tries to explain it in plain language.',
    'intro.note':
      'Interpretations are indicative and probabilistic. NetworkCheck is not a replacement for a professional security audit.',

    'svc.title': 'Exposed services',
    'svc.desc':
      'Shows the programs on your computer listening on the network. A service listening on 0.0.0.0 or * may be reachable by other devices; one on 127.0.0.1 stays local.',
    'svc.cmdMac': 'macOS',
    'svc.cmdWin': 'Windows',
    'svc.cmdLinux': 'Linux',
    'svc.altTitle': 'Alternative commands',
    'svc.altMac': 'macOS — show your local IP addresses:',
    'svc.altLinuxIp': 'Linux — show your local IP addresses:',
    'svc.altLinuxSs': 'Linux — listening ports with process:',
    'svc.winPidTitle': 'Windows — from PID to program',
    'svc.winPid':
      'The last column of netstat is the PID. Open Task Manager (Ctrl+Shift+Esc), Details tab, and look up that PID in the PID column to find the program. If the PID column is hidden, right-click the header → Select columns → PID.',
    'svc.tableTitle': 'Reference ports',
    'svc.thPort': 'Port',
    'svc.thService': 'Service',
    'svc.thNote': 'Note',
    'svc.pasteLabel': 'Paste the command output here',
    'svc.placeholder': 'Paste the terminal output…',
    'svc.analyze': 'Interpret output',
    'svc.clear': 'Clear',

    'net.title': 'Devices on the network',
    'net.desc':
      'Lists the active devices on your local network. Use nmap only on networks and devices you own or are authorized to test.',
    'net.builderTitle': 'Command builder',
    'net.builderDesc':
      'Enter your local IP (find it with the alternative commands above): the app computes the /24 subnet and prepares the nmap command.',
    'net.ipLabel': 'Your local IP',
    'net.ipPlaceholder': 'e.g. 192.168.1.42',
    'net.build': 'Build command',
    'net.builtLabel': 'Generated command',
    'net.pasteLabel': 'Paste the nmap output here',
    'net.placeholder': 'Paste the nmap output…',

    'fw.title': 'Firewall status',
    'fw.desc':
      'Checks whether the operating system firewall is active. An active firewall reduces the reachable surface, but is not an absolute guarantee.',
    'fw.cmdMac': 'macOS',
    'fw.cmdWin': 'Windows',
    'fw.cmdLinux': 'Linux (ufw)',
    'fw.pasteLabel': 'Paste the command output here',
    'fw.placeholder': 'Paste the terminal output…',

    'copy.label': 'Copy',
    'copy.done': 'Copied!',
    'copy.fail': 'Copy failed',
    'results.title': 'Observations',

    'port.21': 'Unencrypted file transfer. Often discouraged.',
    'port.22': 'Encrypted remote access. Restrict access if unused.',
    'port.23': 'UNENCRYPTED remote access. Avoid.',
    'port.53': 'Name resolution (DNS).',
    'port.80': 'Unencrypted web site or service.',
    'port.139': 'Legacy file sharing (NetBIOS).',
    'port.443': 'Encrypted web site or service.',
    'port.445': 'Windows file sharing (SMB). Sensitive if exposed.',
    'port.3389': 'Windows Remote Desktop (RDP). Sensitive if exposed.',
    'port.5000': 'Common local development server.',
    'port.8080': 'Alternative web service, often for development.',
    'port.8765': 'Typical of a manually started Python server.',

    'finding.exposed.title': 'Potentially exposed service: {service} (port {port}/{proto})',
    'finding.exposed.detail':
      'It is listening on {address}, so it may be reachable by other devices on the network. Check whether it really needs to be accessible.',
    'finding.local.title': 'Local service: {service} (port {port}/{proto})',
    'finding.local.detail':
      'Listening locally only (127.0.0.1): it is probably not reachable from the network.',
    'finding.hosts.title': 'Detected {count} devices on the network',
    'finding.hosts.detail':
      'nmap found {count} active hosts. Check that you recognize them all; an unknown device is worth investigating.',
    'finding.open.title': 'Open port: {service} (port {port}/{proto})',
    'finding.open.detail':
      'The device responds on this port. Consider whether the service should be accessible.',
    'finding.fwOn.title': 'Firewall likely active',
    'finding.fwOn.detail':
      'The output indicates an active firewall. A good sign, but not an absolute guarantee.',
    'finding.fwOff.title': 'Firewall likely disabled',
    'finding.fwOff.detail':
      'The output indicates an inactive firewall. Consider enabling it, especially on untrusted networks.',
    'finding.none.title': 'No known pattern recognized',
    'finding.none.detail':
      'No known elements were recognized in the output. Make sure you pasted the full result of one of the suggested commands.',

    'analyze.empty': 'Paste some output to interpret first.',
    'analyze.tooBig': 'Text too long (over 100 KB). Paste only the relevant part.',
    'builder.invalid': 'Invalid IP. Use a format like 192.168.1.42.',

    'disc.title': 'Before you start',
    'disc.p1':
      'NetworkCheck is a personal, educational and diagnostic tool. It does not scan: it guides you and interprets what you paste.',
    'disc.li1':
      'Use scanning commands (such as nmap) only on networks and devices you own or are explicitly authorized to test. Scanning other people’s networks may be a crime.',
    'disc.li2':
      'No data is collected, sent or stored externally. Everything stays on your device (in line with GDPR).',
    'disc.li3':
      'Interpretations are heuristic and probabilistic: they do not replace a security audit.',
    'disc.checkbox': 'I have read and accept',
    'disc.enter': 'Enter',
    'disc.link': 'Disclaimer',

    'footer.privacy':
      'No data leaves your device. Only language and consent are stored.',
    'footer.clear': 'Clear everything',
    'footer.cleared': 'Local data cleared.',
    'footer.author': 'Alessandro Pezzali / pezzaliAPP',
    'footer.offline': 'Works offline after the first load.',
  },
};

/** Lingua di default. @type {string} */
export const DEFAULT_LANG = 'it';

/** Lingua di fallback. @type {string} */
export const FALLBACK_LANG = 'en';

/**
 * Restituisce la stringa tradotta per la chiave indicata, con interpolazione
 * dei segnaposto `{nome}`. Se la chiave manca nella lingua scelta, ricade su EN,
 * infine sulla chiave stessa.
 *
 * @param {string} lang - Codice lingua ('it' | 'en').
 * @param {string} key - Chiave della stringa.
 * @param {Object<string,string|number>} [vars] - Valori per i segnaposto.
 * @returns {string} Testo tradotto e interpolato.
 */
export function t(lang, key, vars = {}) {
  const dict = I18N[lang] || I18N[FALLBACK_LANG];
  let str = dict[key];
  if (str === undefined) str = I18N[FALLBACK_LANG][key];
  if (str === undefined) return key;
  return str.replace(/\{(\w+)\}/g, (match, name) =>
    Object.prototype.hasOwnProperty.call(vars, name) ? String(vars[name]) : match
  );
}
