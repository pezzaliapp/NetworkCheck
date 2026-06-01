/**
 * parser.js — Interprete euristico dell'output incollato dall'utente.
 *
 * Modulo PURO e testabile: nessuna dipendenza dal DOM, nessun effetto collaterale.
 * Riceve testo grezzo (UNTRUSTED) e restituisce strutture dati semplici.
 *
 * Principio di onestà: l'interpretazione è euristica. Non emette verdetti di
 * sicurezza ("sei al sicuro"), solo osservazioni probabilistiche da verificare.
 *
 * Anti-ReDoS: tutte le espressioni regolari sono semplici e lineari, senza
 * quantificatori annidati. L'input viene comunque limitato a monte (vedi app.js).
 *
 * @module parser
 */

/**
 * Dimensione massima di testo accettata dal parser (in caratteri).
 * Coerente con il limite imposto dalla UI (~100 KB).
 * @type {number}
 */
export const MAX_INPUT = 100 * 1024;

/**
 * Tabella di riferimento delle porte note.
 * `risk` è un livello indicativo: 'info' | 'notice' | 'warning'.
 * Non è un giudizio di sicurezza, solo un'indicazione di attenzione.
 *
 * @type {Object<number, {service: string, descKey: string, risk: string}>}
 */
export const KNOWN_PORTS = {
  21: { service: 'FTP', descKey: 'port.21', risk: 'warning' },
  22: { service: 'SSH', descKey: 'port.22', risk: 'notice' },
  23: { service: 'Telnet', descKey: 'port.23', risk: 'warning' },
  53: { service: 'DNS', descKey: 'port.53', risk: 'info' },
  80: { service: 'HTTP', descKey: 'port.80', risk: 'notice' },
  139: { service: 'NetBIOS', descKey: 'port.139', risk: 'warning' },
  443: { service: 'HTTPS', descKey: 'port.443', risk: 'info' },
  445: { service: 'SMB', descKey: 'port.445', risk: 'warning' },
  3389: { service: 'RDP', descKey: 'port.3389', risk: 'warning' },
  5000: { service: 'Server locale', descKey: 'port.5000', risk: 'notice' },
  8080: { service: 'HTTP alt', descKey: 'port.8080', risk: 'notice' },
  8765: { service: 'Python http.server', descKey: 'port.8765', risk: 'notice' },
};

/** Indirizzi che indicano un bind locale (non raggiungibile dalla rete). */
const LOCAL_BINDS = new Set(['127.0.0.1', '::1', 'localhost']);

/** Indirizzi che indicano un bind su tutte le interfacce (esposto). */
const ANY_BINDS = new Set(['0.0.0.0', '*', '::', '[::]', '0.0.0.0.0']);

/**
 * Normalizza l'indirizzo estratto distinguendo bind locale da bind pubblico.
 *
 * @param {string} addr - Indirizzo grezzo (es. "0.0.0.0", "*", "127.0.0.1").
 * @returns {{address: string, exposed: boolean}} Indirizzo normalizzato e se è
 *   potenzialmente esposto sulla rete.
 */
function classifyBind(addr) {
  const a = String(addr || '').trim().toLowerCase();
  if (LOCAL_BINDS.has(a)) return { address: a, exposed: false };
  if (ANY_BINDS.has(a)) return { address: a, exposed: true };
  // Indirizzo IP specifico di una interfaccia: potenzialmente raggiungibile.
  return { address: a, exposed: true };
}

/**
 * Estrae le porte in ascolto da output tipo `lsof`, `netstat`, `ss`.
 *
 * Considera solo le righe che contengono un marcatore di ascolto
 * (LISTEN / LISTENING). Per ogni riga estrae la coppia indirizzo:porta.
 * Gestisce sia il separatore `:` (Linux/Windows) sia `.` (macOS `netstat -an`).
 *
 * @param {string} text - Output grezzo, già validato per dimensione.
 * @returns {Array<{port: number, address: string, exposed: boolean, proto: string}>}
 *   Elenco di socket in ascolto rilevati, senza duplicati.
 */
export function extractListeningPorts(text) {
  const lines = String(text).split(/\r?\n/);
  /** Cattura "addr:porta" o "addr.porta" su indirizzi IPv4, *, 0.0.0.0, ::, localhost. */
  const re = /(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|\[?::\]?|\*|localhost)[:.](\d{1,5})\b/i;
  const seen = new Set();
  const out = [];

  for (const line of lines) {
    if (!/LISTEN/i.test(line)) continue;
    const m = line.match(re);
    if (!m) continue;

    const port = Number(m[2]);
    if (!Number.isInteger(port) || port < 1 || port > 65535) continue;

    const { address, exposed } = classifyBind(m[1]);
    const proto = /\budp\b/i.test(line) ? 'udp' : 'tcp';
    const key = `${proto}:${address}:${port}`;
    if (seen.has(key)) continue;
    seen.add(key);

    out.push({ port, address, exposed, proto });
  }
  return out;
}

/**
 * Estrae gli host rilevati da un output di host discovery `nmap -sn`.
 * Conta le righe "Nmap scan report for ...".
 *
 * @param {string} text - Output grezzo.
 * @returns {Array<string>} Elenco degli host (IP o hostname) rilevati.
 */
export function extractHosts(text) {
  const lines = String(text).split(/\r?\n/);
  const hosts = [];
  const seen = new Set();
  for (const line of lines) {
    const m = line.match(/Nmap scan report for\s+(.+?)\s*$/i);
    if (!m) continue;
    const host = m[1].trim();
    if (seen.has(host)) continue;
    seen.add(host);
    hosts.push(host);
  }
  return hosts;
}

/**
 * Estrae le porte aperte da un output di port scan `nmap` (righe "22/tcp open ...").
 *
 * @param {string} text - Output grezzo.
 * @returns {Array<{port: number, proto: string, service: string}>}
 *   Porte segnalate come "open".
 */
export function extractNmapOpenPorts(text) {
  const lines = String(text).split(/\r?\n/);
  const out = [];
  const seen = new Set();
  for (const line of lines) {
    const m = line.match(/^\s*(\d{1,5})\/(tcp|udp)\s+open\s*(\S*)/i);
    if (!m) continue;
    const port = Number(m[1]);
    if (!Number.isInteger(port) || port < 1 || port > 65535) continue;
    const proto = m[2].toLowerCase();
    const key = `${proto}:${port}`;
    if (seen.has(key)) continue;
    seen.add(key);
    out.push({ port, proto, service: (m[3] || '').trim() });
  }
  return out;
}

/**
 * Rileva lo stato del firewall da output di macOS / Windows / Linux (ufw).
 *
 * @param {string} text - Output grezzo.
 * @returns {{state: ('on'|'off'|'unknown'), source: string}} Stato rilevato e
 *   piattaforma euristicamente riconosciuta.
 */
export function detectFirewallState(text) {
  const t = String(text);
  // macOS socketfilterfw
  if (/firewall is enabled|state\s*=\s*1|state\s*=\s*2/i.test(t)) {
    return { state: 'on', source: 'macos' };
  }
  if (/firewall is disabled|state\s*=\s*0/i.test(t)) {
    return { state: 'off', source: 'macos' };
  }
  // Linux ufw
  if (/status:\s*active/i.test(t)) return { state: 'on', source: 'ufw' };
  if (/status:\s*inactive/i.test(t)) return { state: 'off', source: 'ufw' };
  // Windows netsh advfirewall
  if (/state\s+on\b/i.test(t)) return { state: 'on', source: 'windows' };
  if (/state\s+off\b/i.test(t)) return { state: 'off', source: 'windows' };
  return { state: 'unknown', source: 'unknown' };
}

/**
 * Crea un oggetto "finding" normalizzato.
 *
 * @param {('info'|'notice'|'warning')} level - Livello di attenzione.
 * @param {string} titleKey - Chiave i18n del titolo.
 * @param {string} detailKey - Chiave i18n del dettaglio.
 * @param {Object<string,string|number>} [vars] - Variabili da interpolare nei testi.
 * @returns {{level: string, titleKey: string, detailKey: string, vars: Object}}
 */
function finding(level, titleKey, detailKey, vars = {}) {
  return { level, titleKey, detailKey, vars };
}

/**
 * Analizza in modo euristico un output incollato e produce osservazioni.
 *
 * Riconosce, in ordine di tentativo: porte in ascolto, host nmap, porte aperte
 * nmap, stato firewall. Tutte le osservazioni usano linguaggio probabilistico.
 *
 * @param {string} rawText - Testo incollato dall'utente (UNTRUSTED).
 * @returns {{ok: boolean, errorKey?: string, findings: Array, stats: Object}}
 *   Risultato strutturato. `ok=false` con `errorKey` se l'input non è valido.
 */
export function analyze(rawText) {
  const text = typeof rawText === 'string' ? rawText : '';

  if (text.length === 0) {
    return { ok: false, errorKey: 'analyze.empty', findings: [], stats: {} };
  }
  if (text.length > MAX_INPUT) {
    return { ok: false, errorKey: 'analyze.tooBig', findings: [], stats: {} };
  }

  const findings = [];
  const stats = { listening: 0, exposed: 0, hosts: 0, openPorts: 0 };

  // 1) Porte in ascolto (servizi esposti)
  const listening = extractListeningPorts(text);
  if (listening.length > 0) {
    stats.listening = listening.length;
    for (const sock of listening) {
      const known = KNOWN_PORTS[sock.port];
      const service = known ? known.service : 'sconosciuto';
      if (sock.exposed) {
        stats.exposed += 1;
        const level = known && known.risk === 'warning' ? 'warning' : 'notice';
        findings.push(
          finding(level, 'finding.exposed.title', 'finding.exposed.detail', {
            port: sock.port,
            proto: sock.proto.toUpperCase(),
            service,
            address: sock.address,
          })
        );
      } else {
        findings.push(
          finding('info', 'finding.local.title', 'finding.local.detail', {
            port: sock.port,
            proto: sock.proto.toUpperCase(),
            service,
          })
        );
      }
    }
  }

  // 2) Host discovery (nmap -sn)
  const hosts = extractHosts(text);
  if (hosts.length > 0) {
    stats.hosts = hosts.length;
    findings.push(
      finding('info', 'finding.hosts.title', 'finding.hosts.detail', {
        count: hosts.length,
      })
    );
  }

  // 3) Porte aperte (nmap port scan)
  const openPorts = extractNmapOpenPorts(text);
  if (openPorts.length > 0) {
    stats.openPorts = openPorts.length;
    for (const p of openPorts) {
      const known = KNOWN_PORTS[p.port];
      const service = p.service || (known ? known.service : 'sconosciuto');
      const level = known && known.risk === 'warning' ? 'warning' : 'notice';
      findings.push(
        finding(level, 'finding.open.title', 'finding.open.detail', {
          port: p.port,
          proto: p.proto.toUpperCase(),
          service,
        })
      );
    }
  }

  // 4) Stato firewall
  const fw = detectFirewallState(text);
  if (fw.state === 'on') {
    findings.push(finding('info', 'finding.fwOn.title', 'finding.fwOn.detail'));
  } else if (fw.state === 'off') {
    findings.push(
      finding('warning', 'finding.fwOff.title', 'finding.fwOff.detail')
    );
  }

  // Nessun pattern riconosciuto
  if (findings.length === 0) {
    findings.push(
      finding('info', 'finding.none.title', 'finding.none.detail')
    );
  }

  return { ok: true, findings, stats };
}

/**
 * Calcola il comando `nmap` di host discovery per la subnet /24 a partire da un
 * IP locale fornito dall'utente.
 *
 * @param {string} ip - Indirizzo IPv4 locale (es. "192.168.1.42").
 * @returns {{ok: boolean, command?: string, subnet?: string, errorKey?: string}}
 *   Comando pronto da copiare, oppure errore se l'IP non è valido.
 */
export function buildSubnetScan(ip) {
  const raw = String(ip || '').trim();
  const m = raw.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (!m) {
    return { ok: false, errorKey: 'builder.invalid' };
  }
  const octets = [m[1], m[2], m[3], m[4]].map(Number);
  if (octets.some((o) => o < 0 || o > 255)) {
    return { ok: false, errorKey: 'builder.invalid' };
  }
  const subnet = `${octets[0]}.${octets[1]}.${octets[2]}.0/24`;
  return { ok: true, subnet, command: `nmap -sn ${subnet}` };
}
