/**
 * app.js — Entrypoint e orchestrazione della UI di NetworkCheck.
 *
 * Responsabilità: i18n, gate di consenso (modale accessibile con focus trap),
 * pulsanti "Copia", generatore di comando nmap, collegamento dei riquadri di
 * analisi al parser, gestione preferenze locali e registrazione del service worker.
 *
 * Sicurezza: l'output incollato è UNTRUSTED. I risultati vengono inseriti nel DOM
 * solo con `textContent` / `createElement`, mai con `innerHTML` su dati utente.
 *
 * @module app
 */

import { t, DEFAULT_LANG, FALLBACK_LANG } from './i18n.js';
import { analyze, buildSubnetScan } from './parser.js';

/** Chiavi di localStorage usate dall'app. */
const STORAGE = {
  lang: 'nc_lang',
  consent: 'nc_consent',
};

/** Stato runtime minimale. */
const state = {
  lang: DEFAULT_LANG,
};

/* ------------------------------------------------------------------ */
/* Internazionalizzazione                                              */
/* ------------------------------------------------------------------ */

/**
 * Applica le traduzioni correnti a tutti gli elementi annotati nel DOM e
 * aggiorna `<html lang>`.
 *
 * Supporta gli attributi: `data-i18n` (textContent), `data-i18n-placeholder`,
 * `data-i18n-aria` (aria-label), `data-i18n-title`.
 *
 * @returns {void}
 */
function applyTranslations() {
  document.documentElement.lang = state.lang;

  document.querySelectorAll('[data-i18n]').forEach((el) => {
    el.textContent = t(state.lang, el.getAttribute('data-i18n'));
  });
  document.querySelectorAll('[data-i18n-placeholder]').forEach((el) => {
    el.setAttribute(
      'placeholder',
      t(state.lang, el.getAttribute('data-i18n-placeholder'))
    );
  });
  document.querySelectorAll('[data-i18n-aria]').forEach((el) => {
    el.setAttribute('aria-label', t(state.lang, el.getAttribute('data-i18n-aria')));
  });
  document.querySelectorAll('[data-i18n-title]').forEach((el) => {
    el.setAttribute('title', t(state.lang, el.getAttribute('data-i18n-title')));
  });
}

/**
 * Cambia la lingua corrente, la persiste e riapplica le traduzioni.
 *
 * @param {string} lang - 'it' | 'en'.
 * @returns {void}
 */
function setLang(lang) {
  state.lang = lang === 'en' ? 'en' : 'it';
  try {
    localStorage.setItem(STORAGE.lang, state.lang);
  } catch (_) {
    /* storage non disponibile: si prosegue senza persistenza */
  }
  applyTranslations();
}

/* ------------------------------------------------------------------ */
/* Copia negli appunti                                                 */
/* ------------------------------------------------------------------ */

/**
 * Copia un testo negli appunti usando la Clipboard API, con fallback su
 * `document.execCommand('copy')` per browser/contesti meno recenti.
 *
 * @param {string} text - Testo da copiare.
 * @returns {Promise<boolean>} `true` se la copia è riuscita.
 */
async function copyText(text) {
  if (navigator.clipboard && window.isSecureContext) {
    try {
      await navigator.clipboard.writeText(text);
      return true;
    } catch (_) {
      /* prova il fallback */
    }
  }
  try {
    const ta = document.createElement('textarea');
    ta.value = text;
    ta.setAttribute('readonly', '');
    ta.style.position = 'absolute';
    ta.style.left = '-9999px';
    document.body.appendChild(ta);
    ta.select();
    const ok = document.execCommand('copy');
    document.body.removeChild(ta);
    return ok;
  } catch (_) {
    return false;
  }
}

/**
 * Mostra un feedback temporaneo sul pulsante "Copia".
 *
 * @param {HTMLElement} btn - Il pulsante che ha avviato la copia.
 * @param {boolean} ok - Esito della copia.
 * @returns {void}
 */
function flashCopyFeedback(btn, ok) {
  const original = t(state.lang, 'copy.label');
  btn.textContent = t(state.lang, ok ? 'copy.done' : 'copy.fail');
  btn.classList.add('is-flash');
  window.setTimeout(() => {
    btn.textContent = original;
    btn.classList.remove('is-flash');
  }, 1600);
}

/**
 * Collega tutti i pulsanti con `data-copy-target` (selettore CSS dell'elemento
 * di cui copiare il `textContent`).
 *
 * @returns {void}
 */
function wireCopyButtons() {
  document.querySelectorAll('[data-copy-target]').forEach((btn) => {
    btn.addEventListener('click', async () => {
      const target = document.querySelector(btn.getAttribute('data-copy-target'));
      if (!target) return;
      const ok = await copyText(target.textContent.trim());
      flashCopyFeedback(btn, ok);
    });
  });
}

/* ------------------------------------------------------------------ */
/* Generatore di comando nmap (subnet /24)                             */
/* ------------------------------------------------------------------ */

/**
 * Collega il generatore di comando: legge l'IP locale, calcola la subnet /24 e
 * mostra il comando nmap pronto da copiare.
 *
 * @returns {void}
 */
function wireSubnetBuilder() {
  const input = document.getElementById('builder-ip');
  const button = document.getElementById('builder-run');
  const output = document.getElementById('builder-output');
  const wrap = document.getElementById('builder-result');
  const error = document.getElementById('builder-error');
  if (!input || !button || !output || !wrap || !error) return;

  const run = () => {
    error.textContent = '';
    const result = buildSubnetScan(input.value);
    if (!result.ok) {
      wrap.hidden = true;
      error.textContent = t(state.lang, result.errorKey);
      return;
    }
    output.textContent = result.command;
    wrap.hidden = false;
  };

  button.addEventListener('click', run);
  input.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') {
      e.preventDefault();
      run();
    }
  });
}

/* ------------------------------------------------------------------ */
/* Riquadri di analisi                                                 */
/* ------------------------------------------------------------------ */

/**
 * Costruisce e accoda un elemento "finding" sicuro (solo textContent).
 *
 * @param {HTMLElement} container - Contenitore dei risultati.
 * @param {{level: string, titleKey: string, detailKey: string, vars: Object}} f
 *   Finding restituito dal parser.
 * @returns {void}
 */
function appendFinding(container, f) {
  const article = document.createElement('article');
  article.className = `finding finding--${f.level}`;

  const badge = document.createElement('span');
  badge.className = 'finding__badge';
  badge.textContent = f.level;
  badge.setAttribute('aria-hidden', 'true');

  const title = document.createElement('h3');
  title.className = 'finding__title';
  title.textContent = t(state.lang, f.titleKey, f.vars);

  const detail = document.createElement('p');
  detail.className = 'finding__detail';
  detail.textContent = t(state.lang, f.detailKey, f.vars);

  article.appendChild(badge);
  article.appendChild(title);
  article.appendChild(detail);
  container.appendChild(article);
}

/**
 * Collega un singolo riquadro di analisi (textarea + pulsante + risultati) al
 * parser. Tutti i riquadri condividono lo stesso motore `analyze()`.
 *
 * @param {HTMLElement} root - Sezione che contiene gli elementi `data-role`.
 * @returns {void}
 */
function wireAnalyzer(root) {
  const input = root.querySelector('[data-role="input"]');
  const runBtn = root.querySelector('[data-role="run"]');
  const clearBtn = root.querySelector('[data-role="clear"]');
  const results = root.querySelector('[data-role="results"]');
  if (!input || !runBtn || !results) return;

  const render = () => {
    results.replaceChildren();
    const outcome = analyze(input.value);

    if (!outcome.ok) {
      const p = document.createElement('p');
      p.className = 'results__error';
      p.setAttribute('role', 'alert');
      p.textContent = t(state.lang, outcome.errorKey);
      results.appendChild(p);
      return;
    }

    const heading = document.createElement('h3');
    heading.className = 'results__title';
    heading.textContent = t(state.lang, 'results.title');
    results.appendChild(heading);

    outcome.findings.forEach((f) => appendFinding(results, f));
  };

  runBtn.addEventListener('click', render);
  if (clearBtn) {
    clearBtn.addEventListener('click', () => {
      input.value = '';
      results.replaceChildren();
      input.focus();
    });
  }
}

/**
 * Collega tutti i riquadri di analisi presenti nella pagina.
 * @returns {void}
 */
function wireAnalyzers() {
  document.querySelectorAll('[data-analyzer]').forEach(wireAnalyzer);
}

/* ------------------------------------------------------------------ */
/* Gate di consenso (modale accessibile)                               */
/* ------------------------------------------------------------------ */

/**
 * Inizializza la modale di disclaimer: focus trap, chiusura solo dopo consenso,
 * memorizzazione del consenso. Riapribile dal link nel footer.
 *
 * @returns {void}
 */
function initConsentGate() {
  const modal = document.getElementById('disclaimer');
  const checkbox = document.getElementById('disclaimer-accept');
  const enterBtn = document.getElementById('disclaimer-enter');
  const openLink = document.getElementById('open-disclaimer');
  if (!modal || !checkbox || !enterBtn) return;

  let lastFocus = null;

  const focusables = () =>
    Array.from(
      modal.querySelectorAll(
        'a[href], button:not([disabled]), input, [tabindex]:not([tabindex="-1"])'
      )
    ).filter((el) => el.offsetParent !== null || el === checkbox);

  /** Mantiene il focus dentro la modale (focus trap). */
  const onKeydown = (e) => {
    if (e.key !== 'Tab') return;
    const items = focusables();
    if (items.length === 0) return;
    const first = items[0];
    const last = items[items.length - 1];
    if (e.shiftKey && document.activeElement === first) {
      e.preventDefault();
      last.focus();
    } else if (!e.shiftKey && document.activeElement === last) {
      e.preventDefault();
      first.focus();
    }
  };

  const open = () => {
    lastFocus = document.activeElement;
    modal.hidden = false;
    document.body.classList.add('modal-open');
    document.addEventListener('keydown', onKeydown);
    window.setTimeout(() => checkbox.focus(), 0);
  };

  const close = () => {
    modal.hidden = true;
    document.body.classList.remove('modal-open');
    document.removeEventListener('keydown', onKeydown);
    if (lastFocus && typeof lastFocus.focus === 'function') lastFocus.focus();
  };

  checkbox.addEventListener('change', () => {
    enterBtn.disabled = !checkbox.checked;
  });

  enterBtn.addEventListener('click', () => {
    if (!checkbox.checked) return;
    try {
      localStorage.setItem(STORAGE.consent, '1');
    } catch (_) {
      /* prosegue senza persistenza */
    }
    close();
  });

  if (openLink) {
    openLink.addEventListener('click', (e) => {
      e.preventDefault();
      open();
    });
  }

  let consented = false;
  try {
    consented = localStorage.getItem(STORAGE.consent) === '1';
  } catch (_) {
    consented = false;
  }

  enterBtn.disabled = !checkbox.checked;
  if (!consented) open();
}

/* ------------------------------------------------------------------ */
/* Footer: cancella tutto                                              */
/* ------------------------------------------------------------------ */

/**
 * Collega il pulsante "Cancella tutto": rimuove le preferenze locali (lingua e
 * consenso). Non vengono mai salvati i contenuti incollati.
 *
 * @returns {void}
 */
function wireClearAll() {
  const btn = document.getElementById('clear-all');
  const feedback = document.getElementById('clear-feedback');
  if (!btn) return;
  btn.addEventListener('click', () => {
    try {
      localStorage.removeItem(STORAGE.lang);
      localStorage.removeItem(STORAGE.consent);
    } catch (_) {
      /* nulla da fare */
    }
    if (feedback) feedback.textContent = t(state.lang, 'footer.cleared');
  });
}

/* ------------------------------------------------------------------ */
/* Toggle lingua                                                       */
/* ------------------------------------------------------------------ */

/**
 * Collega il pulsante di cambio lingua.
 * @returns {void}
 */
function wireLangToggle() {
  const btn = document.getElementById('lang-toggle');
  if (!btn) return;
  btn.addEventListener('click', () => {
    setLang(state.lang === 'it' ? 'en' : 'it');
  });
}

/* ------------------------------------------------------------------ */
/* Service worker                                                      */
/* ------------------------------------------------------------------ */

/**
 * Registra il service worker per il funzionamento offline (best effort).
 * @returns {void}
 */
function registerServiceWorker() {
  if (!('serviceWorker' in navigator)) return;
  window.addEventListener('load', () => {
    navigator.serviceWorker.register('./sw.js').catch(() => {
      /* la registrazione può fallire (es. file://): l'app resta usabile */
    });
  });
}

/* ------------------------------------------------------------------ */
/* Avvio                                                               */
/* ------------------------------------------------------------------ */

/**
 * Punto di ingresso: legge le preferenze, collega gli handler e avvia l'app.
 * @returns {void}
 */
function init() {
  let saved = null;
  try {
    saved = localStorage.getItem(STORAGE.lang);
  } catch (_) {
    saved = null;
  }
  if (saved === 'it' || saved === 'en') {
    state.lang = saved;
  } else {
    const nav = (navigator.language || FALLBACK_LANG).slice(0, 2).toLowerCase();
    state.lang = nav === 'it' ? 'it' : DEFAULT_LANG;
  }

  applyTranslations();
  wireLangToggle();
  wireCopyButtons();
  wireSubnetBuilder();
  wireAnalyzers();
  wireClearAll();
  initConsentGate();
  registerServiceWorker();
}

if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', init);
} else {
  init();
}
