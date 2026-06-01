/**
 * tests/parser.test.mjs — Suite di test del modulo puro `js/parser.js`.
 *
 * Esegui con:  node tests/parser.test.mjs
 *
 * Non fa parte del bundle della PWA: non è referenziato dall'app né dal service
 * worker. Serve solo a verificare l'interprete euristico in modo riproducibile.
 */

import {
  extractListeningPorts,
  extractHosts,
  extractNmapOpenPorts,
  detectFirewallState,
  buildSubnetScan,
  analyze,
} from '../js/parser.js';

let failures = 0;
/** Asserzione minimale con messaggio. */
function ok(cond, msg) {
  if (cond) {
    console.log('  ok:', msg);
  } else {
    console.error('FAIL:', msg);
    failures += 1;
  }
}

/* --- Caso reale lsof: bind '*' e loopback IPv6 -------------------------- */
const lsofReal = `COMMAND     PID  USER  FD  TYPE  DEVICE  SIZE/OFF  NODE NAME
Creative   9738 ...  IPv4 ... TCP 127.0.0.1:59595 (LISTEN)
ControlCe 78040 ...  IPv4 ... TCP *:7000 (LISTEN)
ControlCe 78040 ...  IPv4 ... TCP *:5000 (LISTEN)
rapportd  78111 ...  IPv4 ... TCP *:59776 (LISTEN)
OneDrive  78764 ...  IPv6 ... TCP [::1]:42050 (LISTEN)`;

const lsofPorts = extractListeningPorts(lsofReal);
const by = (p) => lsofPorts.find((s) => s.port === p);

ok(lsofPorts.length === 5, 'lsof reale: 5 socket riconosciuti (incluso IPv6)');
ok(by(5000) && by(5000).exposed, '*:5000 => esposto');
ok(by(7000) && by(7000).exposed, '*:7000 => esposto');
ok(by(59776) && by(59776).exposed, '*:59776 => esposto');
ok(by(59595) && by(59595).exposed === false, '127.0.0.1:59595 => locale');
ok(by(42050) && by(42050).exposed === false, '[::1]:42050 => loopback IPv6 locale');

const lsofAnalysis = analyze(lsofReal);
ok(lsofAnalysis.stats.exposed === 3, 'analyze: 3 servizi esposti');
ok(lsofAnalysis.stats.listening === 5, 'analyze: 5 servizi in ascolto');
// La porta 5000 è nota (notice) ma in bind '*' deve risultare comunque esposta.
const f5000 = lsofAnalysis.findings.find(
  (f) => f.titleKey === 'finding.exposed.title' && f.vars.port === 5000
);
ok(!!f5000, 'porta 5000 nota ma esposta: presente tra i finding "exposed"');
ok(f5000 && f5000.level === 'notice', 'porta 5000 esposta => livello notice');

/* --- IPv6 wildcard tra parentesi (ss / Windows) ------------------------ */
const v6any = extractListeningPorts('tcp LISTEN 0 128 [::]:22 [::]:* users:(("sshd"))');
ok(v6any.length === 1 && v6any[0].port === 22 && v6any[0].exposed, '[::]:22 => esposto');

/* --- Altri formati già supportati -------------------------------------- */
ok(
  extractListeningPorts('  TCP    0.0.0.0:445    0.0.0.0:0    LISTENING    4')[0].exposed,
  'netstat Windows 0.0.0.0:445 => esposto'
);
ok(
  extractListeningPorts('tcp4 0 0 *.8765 *.* LISTEN')[0].exposed,
  'netstat macOS *.8765 => esposto'
);
ok(
  extractListeningPorts('tcp4 0 0 ::1.5000 *.* LISTEN')[0].exposed === false,
  'netstat macOS ::1.5000 => loopback IPv6 locale'
);

/* --- Host discovery e port scan nmap ----------------------------------- */
ok(
  extractHosts('Nmap scan report for 192.168.1.1\nNmap scan report for 192.168.1.42').length === 2,
  'nmap: 2 host'
);
ok(extractNmapOpenPorts('22/tcp open ssh\n443/tcp closed https').length === 1, 'nmap: 1 porta aperta');

/* --- Firewall ---------------------------------------------------------- */
ok(detectFirewallState('Firewall is enabled. (State = 1)').state === 'on', 'firewall macOS attivo');
ok(detectFirewallState('Status: inactive').state === 'off', 'firewall ufw inattivo');
ok(detectFirewallState('State                 ON').state === 'on', 'firewall Windows attivo');

/* --- Generatore subnet ------------------------------------------------- */
ok(buildSubnetScan('192.168.1.42').command === 'nmap -sn 192.168.1.0/24', 'builder subnet /24');
ok(!buildSubnetScan('999.1.1.1').ok, 'builder: ottetto non valido');
ok(!buildSubnetScan('abc').ok, 'builder: formato non valido');

/* --- Limiti di input --------------------------------------------------- */
ok(!analyze('').ok, 'input vuoto rifiutato');
ok(!analyze('x'.repeat(200000)).ok, 'input troppo grande rifiutato');

console.log(
  failures === 0 ? '\nTUTTI I TEST PASSANO' : `\n${failures} TEST FALLITI`
);
process.exit(failures === 0 ? 0 : 1);
