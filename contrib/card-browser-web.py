#!/usr/bin/env python3
#
# Web-based, read-only filesystem browser for an inserted SIM/USIM/ISIM card, built on
# the same pySim-shell primitives (RuntimeLchan.select_file/read_binary/read_record/
# retrieve_data, CardFile.get_selectables/decode_hex/decode_record_hex, ...).
#
# The file tree is discovered lazily: only the children of a directory the user actually
# expands are queried from the card, and both directory listings and file content reads
# are cached for as long as the same card stays inserted.
#
# (C) 2026 by Bjoern Riemer <bjoern.riemer@fokus.fraunhofer.de>
#     Note: File generated with AI assistance
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

import argparse
import json
import logging
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit, parse_qs

from osmocom.utils import JsonEncoder

from pySim.transport import init_reader, argparse_add_reader_args
from pySim.card_browser import CardSession
from pySim.card_key_provider import card_key_provider_argparse_add_args, card_key_provider_init
from pySim.exceptions import NoCardError
from pySim.log import PySimLogger

log = PySimLogger.get(Path(__file__).stem)

option_parser = argparse.ArgumentParser(
    description='Browse the filesystem of an inserted SIM/USIM/ISIM card on a local webpage',
    formatter_class=argparse.ArgumentDefaultsHelpFormatter)
option_parser.add_argument("--verbose", help="Enable verbose logging", action='store_true', default=False)
option_parser.add_argument("--http-host", default='127.0.0.1',
                            help="Address to bind the web server to (use 0.0.0.0 to allow access "
                                 "from other hosts on the network)")
option_parser.add_argument("--http-port", type=int, default=8000, help="TCP port for the web server")
argparse_add_reader_args(option_parser)
card_key_provider_argparse_add_args(option_parser)


class CardMonitor(threading.Thread):
    """Background thread that waits for card insertions/re-insertions and (re-)detects the
    card's profile via CardSession.set_card(). Session state (and its caches) are only ever
    touched under session.lock -- see CardSession for why."""

    # How often (seconds) to actively verify a card we believe is present hasn't been
    # silently removed -- see _check_liveness(). A card being physically pulled from the
    # reader is *usually* caught immediately when a foreground read/list/verify_adm request
    # next touches the card (CardSession invalidates itself then -- see
    # CardSession._invalidate_removed()), but if nothing happens to read the card again
    # (e.g. everything the user had open was already cached), nothing else would ever notice.
    LIVENESS_POLL_INTERVAL = 2

    def __init__(self, sl, session: CardSession):
        super().__init__(daemon=True)
        self.sl = sl
        self.session = session
        self.status = 'waiting'  # 'waiting' | 'detecting' | 'ready' | 'error'

    def run(self):
        first = True
        while True:
            # Note: 'waiting' is only set here for the very first iteration (see __init__);
            # once a card has been read, we keep reporting its last known status while we
            # block waiting for the *next* change -- the card is still physically present
            # and perfectly browsable in the meantime, so flipping back to 'waiting' here
            # would be misleading. Once a card has been seen, wait with a bounded timeout
            # instead of blocking forever, so we get a regular tick to run the liveness check
            # below even while no new card has actually been (re-)inserted.
            try:
                self.sl.wait_for_card(timeout=None if first else self.LIVENESS_POLL_INTERVAL,
                                      newcardonly=not first)
            except NoCardError:
                # On the first iteration this can only mean "no card yet" (no timeout was
                # set). On later iterations it just means our poll interval elapsed with no
                # *new* card having appeared -- use the opportunity to verify the card we
                # already know about hasn't quietly disappeared.
                if not first:
                    self._check_liveness()
                continue
            except Exception as e:
                # Note: this runs in a background thread, so Ctrl-C (SIGINT) is delivered to
                # the main thread (blocked in server.serve_forever()), never here -- any
                # exception here is a genuine reader/transport error, not a user cancellation.
                log.warning("wait_for_card failed: %s", e)
                time.sleep(1)
                continue
            first = False

            self.status = 'detecting'
            with self.session.lock:
                try:
                    self.session.set_card(self.sl)
                    self.status = 'ready' if self.session.rs else 'error'
                except Exception as e:
                    log.exception("Failed to detect card")
                    self.session._invalidate_removed(str(e))
                    self.status = 'error'

    def _check_liveness(self):
        """Actively confirm that a card CardSession believes is still connected hasn't been
        silently removed. Necessary because the *reactive* invalidation in CardSession (on a
        failed select/read/verify_chv) only fires when something actually tries to talk to
        the card again -- if the browser only ever re-serves already-cached tree/file
        content (including across a page reload, since that's server-side cache, not just
        the browser's), a removed card would otherwise go unnoticed indefinitely."""
        with self.session.lock:
            if self.session.rs is None:
                return
            try:
                self.sl.get_atr()
            except NoCardError as e:
                self.session._invalidate_removed(str(e))
                self.status = 'error'
            except Exception as e:
                # Not actionable from a background liveness probe -- leave state as-is and
                # let the next real card access (or the next liveness tick) surface it.
                log.warning("Card liveness check failed: %s", e)


# Fully static page -- all dynamic data comes from /api/* as JSON and is rendered
# client-side using textContent/createElement (never innerHTML), so untrusted card
# content (file contents, decoded field values, ...) can never be interpreted as
# HTML/script. CSS/JS are served as separate same-origin files so the CSP below can
# forbid 'unsafe-inline'.
PAGE_HTML = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Card Browser</title>
<link rel="stylesheet" href="/style.css">
</head>
<body>
<button id="theme-toggle" type="button" aria-pressed="false" title="Toggle dark mode"></button>
<h1>Card Browser <span id="status" class="status status-waiting">waiting</span>
  <button id="auth-button" type="button">Authenticate (ADM)</button>
</h1>
<div id="cardinfo"></div>
<div id="auth-panel">
  <label>ADM PIN: <input id="auth-pin" type="password" autocomplete="off"></label>
  <label><input id="auth-hex" type="checkbox"> hex-encoded (16 hex chars)</label>
  <button id="auth-submit" type="button">Submit</button>
  <button id="auth-cancel" type="button">Cancel</button>
</div>
<div id="auth-msg"></div>
<div id="error-box"></div>
<div id="layout">
  <div id="tree-pane">
    <h2>Filesystem</h2>
    <ul id="tree"></ul>
  </div>
  <div id="detail-pane">
    <div id="detail-header">
      <h2 id="detail-title">Select a file to view its contents</h2>
      <button id="reload-button" type="button" title="Reload the currently selected item from the card" disabled>&#x27F3; Reload</button>
    </div>
    <div id="detail-desc"></div>
    <div id="detail-body"></div>
  </div>
</div>
<script src="/script.js"></script>
</body>
</html>
"""

PAGE_CSS = """
:root {
  color-scheme: light;
  --bg: #ffffff;
  --fg: #0f172a;
  --muted: #64748b;
  --border: #e5e7eb;
  --panel-bg: #ffffff;
  --code-bg: rgba(15, 23, 42, 0.05);
  --hover-bg: #f1f5f9;
  --selected-bg: #dbeafe;
  --tree-default: #1e293b;
  --tree-adf: #7c3aed;
  --tree-df: #0f766e;
  --tree-special: #b45309;
  --tree-summary: #2563eb;
  --tree-fid: #94a3b8;
  --tree-error: #991b1b;
  --tree-empty: #94a3b8;
  --dt-fg: #334155;
  --btn-bg: #f8fafc;
  --btn-fg: #334155;
  --btn-border: #cbd5e1;
  --success-bg: #dcfce7;
  --success-fg: #166534;
  --success-border: #bbf7d0;
  --error-bg: #fee2e2;
  --error-fg: #991b1b;
  --warn-bg: #fef3c7;
  --warn-fg: #92400e;
  --waiting-bg: #e2e8f0;
  --waiting-fg: #334155;
}
[data-theme="dark"] {
  color-scheme: dark;
  --bg: #0f172a;
  --fg: #e2e8f0;
  --muted: #94a3b8;
  --border: #334155;
  --panel-bg: #1e293b;
  --code-bg: rgba(255, 255, 255, 0.06);
  --hover-bg: #334155;
  --selected-bg: #1e3a5f;
  --tree-default: #e2e8f0;
  --tree-adf: #c4b5fd;
  --tree-df: #5eead4;
  --tree-special: #fbbf24;
  --tree-summary: #93c5fd;
  --tree-fid: #94a3b8;
  --tree-error: #fca5a5;
  --tree-empty: #94a3b8;
  --dt-fg: #cbd5e1;
  --btn-bg: #1e293b;
  --btn-fg: #e2e8f0;
  --btn-border: #475569;
  --success-bg: #14532d;
  --success-fg: #86efac;
  --success-border: #166534;
  --error-bg: #450a0a;
  --error-fg: #fca5a5;
  --warn-bg: #451a03;
  --warn-fg: #fcd34d;
  --waiting-bg: #334155;
  --waiting-fg: #cbd5e1;
}
body { font-family: system-ui, -apple-system, sans-serif; margin: 1.5rem 2rem;
      background: var(--bg); color: var(--fg); }
h1 { font-size: 1.4rem; display: flex; align-items: center; gap: 0.6rem; }
h2 { font-size: 1.0rem; margin: 0 0 0.5rem; }
#theme-toggle { position: fixed; top: 1rem; right: 1.2rem; font-size: 0.8rem;
               padding: 0.25rem 0.7rem; border-radius: 999px; border: 1px solid var(--btn-border);
               background: var(--btn-bg); color: var(--btn-fg); cursor: pointer; }
.status { display: inline-block; padding: 0.15rem 0.6rem; border-radius: 999px;
         font-size: 0.8rem; font-weight: 600; }
.status-waiting  { background: var(--waiting-bg); color: var(--waiting-fg); }
.status-detecting{ background: var(--warn-bg); color: var(--warn-fg); }
.status-ready    { background: var(--success-bg); color: var(--success-fg); }
.status-error    { background: var(--error-bg); color: var(--error-fg); }
#cardinfo { color: var(--muted); font-size: 0.9rem; margin-bottom: 0.4rem; }
#auth-button { font-size: 0.8rem; padding: 0.2rem 0.7rem; border-radius: 999px;
              border: 1px solid var(--btn-border); background: var(--btn-bg); color: var(--btn-fg);
              cursor: pointer; }
#auth-button.authenticated { background: var(--success-bg); color: var(--success-fg);
                             border-color: var(--success-border); }
#auth-panel { display: none; align-items: center; gap: 0.6rem; flex-wrap: wrap; margin-bottom: 0.6rem;
             font-size: 0.9rem; }
#auth-panel input[type=password] { padding: 0.15rem 0.4rem; }
#auth-msg { font-size: 0.85rem; margin-bottom: 0.6rem; }
#auth-msg.success { color: var(--success-fg); }
#auth-msg.failure { color: var(--error-fg); }
#error-box { display: none; background: var(--error-bg); color: var(--error-fg); padding: 0.8rem;
            border-radius: 8px; margin-bottom: 1rem; white-space: pre-wrap; }
#layout { display: flex; gap: 1.5rem; align-items: flex-start; }
#tree-pane { flex: 0 0 340px; border: 1px solid var(--border); border-radius: 8px; padding: 0.8rem;
            max-height: 80vh; overflow: auto; background: var(--panel-bg); }
#detail-pane { flex: 1; border: 1px solid var(--border); border-radius: 8px; padding: 0.8rem;
              min-width: 0; background: var(--panel-bg); }
ul#tree, #tree ul { list-style: none; margin: 0; padding-left: 1.1rem; }
#tree { padding-left: 0; }
#tree li { margin: 0.05rem 0; }
#tree .label { cursor: pointer; padding: 0.1rem 0.3rem; border-radius: 4px; white-space: nowrap;
              color: var(--tree-default); }
#tree .label:hover { background: var(--hover-bg); }
#tree .label.selected { background: var(--selected-bg); font-weight: 600; }
#tree .label.branch::before { content: "\\25b8 "; display: inline-block; width: 0.9em; }
#tree .label.branch.expanded::before { content: "\\25be "; }
#tree .label.leaf::before { content: "\\2022 "; display: inline-block; width: 0.9em; color: var(--tree-fid); }
#tree .kind-adf > .label, #tree .kind-mf > .label { color: var(--tree-adf); }
#tree .kind-df > .label { color: var(--tree-df); }
#tree .label.special { color: var(--tree-special); }
#tree .label.special.leaf::before { content: "\\2699 "; color: var(--tree-special); }
#tree .kind-summary > .label { color: var(--tree-summary); font-weight: 600; }
#tree .kind-summary > .label.leaf::before { content: "\\2139 "; color: var(--tree-summary); }
#tree .label.missing { text-decoration: line-through; opacity: 0.6; }
#tree .fid { color: var(--tree-fid); font-size: 0.85em; }
#tree .tree-error { color: var(--tree-error); font-size: 0.9em; padding-left: 1.2em; }
#tree .tree-empty { color: var(--tree-empty); font-size: 0.9em; padding-left: 1.2em; }
#detail-header { display: flex; align-items: center; gap: 0.6rem; }
#detail-header h2 { margin: 0; flex: 1; }
#reload-button { font-size: 0.8rem; padding: 0.2rem 0.7rem; border-radius: 999px;
                border: 1px solid var(--btn-border); background: var(--btn-bg); color: var(--btn-fg);
                cursor: pointer; }
#reload-button:disabled { opacity: 0.5; cursor: default; }
#detail-desc { color: var(--muted); font-size: 0.9rem; font-style: italic; margin: -0.3rem 0 0.6rem; }
table { border-collapse: collapse; width: 100%; margin: 0.4rem 0 1rem; }
th, td { text-align: left; padding: 0.25rem 0.5rem; border-bottom: 1px solid var(--border);
        vertical-align: top; }
th { width: 9rem; color: var(--muted); font-weight: 600; }
pre { background: var(--code-bg); color: var(--fg); border-radius: 6px; padding: 0.6rem 0.8rem;
     overflow-x: auto; white-space: pre-wrap; word-break: break-all; }
dl { margin: 0.2rem 0; }
dt { font-weight: 600; color: var(--dt-fg); }
dd { margin: 0 0 0.3rem 1.2rem; }
.section-title { font-weight: 600; color: var(--dt-fg); margin: 0.8rem 0 0.2rem; }
.error { color: var(--error-fg); }
.muted { color: var(--muted); }
"""

PAGE_JS = """
"use strict";

const statusEl = document.getElementById('status');
const cardinfoEl = document.getElementById('cardinfo');
const errorBox = document.getElementById('error-box');
const treeEl = document.getElementById('tree');
const detailTitle = document.getElementById('detail-title');
const detailDesc = document.getElementById('detail-desc');
const detailBody = document.getElementById('detail-body');
const reloadButton = document.getElementById('reload-button');

const authButton = document.getElementById('auth-button');
const authPanel = document.getElementById('auth-panel');
const authPin = document.getElementById('auth-pin');
const authHex = document.getElementById('auth-hex');
const authSubmit = document.getElementById('auth-submit');
const authCancel = document.getElementById('auth-cancel');
const authMsg = document.getElementById('auth-msg');

const THEME_KEY = 'card-browser-theme';
const themeToggle = document.getElementById('theme-toggle');

function applyTheme(theme) {
  document.documentElement.setAttribute('data-theme', theme);
  themeToggle.textContent = theme === 'dark' ? '☀️ Light mode' : '🌙 Dark mode';
  themeToggle.setAttribute('aria-pressed', theme === 'dark' ? 'true' : 'false');
}

function initTheme() {
  let theme = localStorage.getItem(THEME_KEY);
  if (theme !== 'light' && theme !== 'dark') {
    theme = (window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches)
        ? 'dark' : 'light';
  }
  applyTheme(theme);
}

themeToggle.addEventListener('click', () => {
  const next = document.documentElement.getAttribute('data-theme') === 'dark' ? 'light' : 'dark';
  localStorage.setItem(THEME_KEY, next);
  applyTheme(next);
});

initTheme();

const STRUCTURE_LABELS = {
  transparent: 'Transparent EF',
  linear_fixed: 'Linear Fixed EF',
  cyclic: 'Cyclic EF',
  ber_tlv: 'BER-TLV EF',
  ara_m_rules: 'ARA-M Access Rules',
  gp_data_objects: 'GlobalPlatform Security Domain',
  card_summary: 'Card Summary',
};

function admText(adm_known) {
  if (adm_known === true) return 'Known (ADM1 key on record)';
  if (adm_known === false) return 'NOT known (no ADM1 key on record for this ICCID)';
  return 'Not configured (no ADM key database file found)';
}

let lastAtr = undefined;
let selectedLabel = null;
let currentPath = null;
let admVerified = false;
const treeCache = new Map();     // path -> children[] (client-side mirror of the server cache)
const labelsByPath = new Map();  // path -> tree <span class="label"> element, for the missing-file indicator

function el(tag, opts) {
  const e = document.createElement(tag);
  if (opts) {
    if (opts.text !== undefined) e.textContent = opts.text;
    if (opts.class) e.className = opts.class;
  }
  return e;
}

function row(table, label, value) {
  const tr = el('tr');
  tr.appendChild(el('th', {text: label}));
  const td = el('td');
  if (value instanceof Node) td.appendChild(value); else td.textContent = value;
  tr.appendChild(td);
  table.appendChild(tr);
}

// Render an arbitrary decoded-file JSON value as a safe (textContent-only) nested
// <dl>/<ul> structure -- values here originate from card content and must never be
// interpreted as HTML.
function renderJsonValue(value) {
  if (value === null || value === undefined) {
    return el('span', {text: 'null', class: 'muted'});
  }
  if (Array.isArray(value)) {
    const ul = el('ul');
    value.forEach((item) => {
      const li = el('li');
      li.appendChild(renderJsonValue(item));
      ul.appendChild(li);
    });
    return ul;
  }
  if (typeof value === 'object') {
    const dl = el('dl');
    for (const key of Object.keys(value)) {
      dl.appendChild(el('dt', {text: key}));
      const dd = el('dd');
      dd.appendChild(renderJsonValue(value[key]));
      dl.appendChild(dd);
    }
    return dl;
  }
  return document.createTextNode(String(value));
}

function renderFileContent(data) {
  detailBody.textContent = '';
  if (!data.exists) {
    detailBody.appendChild(el('p', {text: data.error || 'Not available', class: 'error'}));
    return;
  }
  if (data.error) {
    detailBody.appendChild(el('p', {text: data.error, class: 'error'}));
    return;
  }

  const t = el('table');
  row(t, 'Type', STRUCTURE_LABELS[data.structure] || data.structure);
  detailBody.appendChild(t);

  if (data.structure === 'transparent') {
    detailBody.appendChild(el('div', {text: 'Raw', class: 'section-title'}));
    detailBody.appendChild(el('pre', {text: data.raw || '(empty)'}));
    detailBody.appendChild(el('div', {text: 'Decoded', class: 'section-title'}));
    if (data.decode_error) {
      detailBody.appendChild(el('p', {text: 'Could not decode: ' + data.decode_error, class: 'error'}));
    } else {
      detailBody.appendChild(renderJsonValue(data.decoded));
    }
  } else if (data.structure === 'linear_fixed' || data.structure === 'cyclic') {
    detailBody.appendChild(el('p', {text: data.num_records + ' record(s), ' +
        data.record_len + ' bytes each', class: 'muted'}));
    data.records.forEach((rec) => {
      detailBody.appendChild(el('div', {text: 'Record ' + rec.record_nr, class: 'section-title'}));
      detailBody.appendChild(el('pre', {text: rec.raw || '(empty)'}));
      if (rec.decode_error) {
        detailBody.appendChild(el('p', {text: 'Could not decode: ' + rec.decode_error, class: 'error'}));
      } else if (rec.decoded !== null) {
        detailBody.appendChild(renderJsonValue(rec.decoded));
      }
    });
  } else if (data.structure === 'ber_tlv') {
    if (data.tags.length === 0) {
      detailBody.appendChild(el('p', {text: '(no tags present)', class: 'muted'}));
    }
    data.tags.forEach((entry) => {
      detailBody.appendChild(el('div', {text: 'Tag ' + entry.tag, class: 'section-title'}));
      detailBody.appendChild(el('pre', {text: entry.raw || '(empty)'}));
    });
  } else if (data.structure === 'ara_m_rules') {
    // ARA-M has no regular files -- this is the same GET DATA [All] access-rule listing
    // pySim-shell's do_aram_get_all shows.
    if (data.rules.length === 0) {
      detailBody.appendChild(el('p', {text: 'No access rules configured', class: 'muted'}));
    }
    data.rules.forEach((rule, i) => {
      detailBody.appendChild(el('div', {text: 'Rule ' + (i + 1), class: 'section-title'}));
      const rt = el('table');
      if (rule.package) row(rt, 'Package', rule.package);
      row(rt, 'AID', rule.aid || 'Not available');
      row(rt, 'Certificate hash', rule.device_app_id || 'Not available');
      row(rt, 'Android permissions', rule.android_permissions || 'Not available');
      detailBody.appendChild(rt);
    });
  } else if (data.structure === 'gp_data_objects') {
    // Security Domains (e.g. ISD) don't have regular files either -- this is a sweep of the
    // read-only GlobalPlatform GET DATA objects pySim-shell's do_get_data can retrieve one
    // at a time; not every object is supported by every card, hence the per-object errors.
    data.objects.forEach((obj) => {
      detailBody.appendChild(el('div', {text: obj.name + ' (' + obj.tag + ')', class: 'section-title'}));
      if (obj.error) {
        detailBody.appendChild(el('p', {text: obj.error, class: 'muted'}));
      } else {
        detailBody.appendChild(renderJsonValue(obj.decoded));
      }
    });
  } else if (data.structure === 'card_summary') {
    // Same overview card-summary.py/card-summary-web.py show (ICCID/IMSI/SPN/EHPLMN/
    // ARA-M/ADM key database status) -- not tied to any single file, just a synthetic
    // tree entry for convenience.
    const s = data.summary;

    const t0 = el('table');
    row(t0, 'Card type', s.card_type || 'Unknown');
    row(t0, 'ATR', s.atr || 'Unknown');
    detailBody.appendChild(t0);

    if (s.applications && s.applications.length) {
      detailBody.appendChild(el('div', {text: 'Applications', class: 'section-title'}));
      const ul = el('ul');
      for (const app of s.applications) {
        ul.appendChild(el('li', {text: app.aid + ' (' + app.name + ')'}));
      }
      detailBody.appendChild(ul);
    }

    const st = el('table');
    row(st, 'ICCID', s.iccid || 'Not available');
    row(st, 'ADM key database', admText(s.adm_known));
    row(st, 'IMSI', s.imsi || 'Not available');
    if (s.spn) {
      row(st, 'SPN', (s.spn.name || 'Not available') +
          ' (show in HPLMN: ' + s.spn.show_in_hplmn + ', hide in OPLMN: ' + s.spn.hide_in_oplmn + ')');
    } else {
      row(st, 'SPN', 'Not available');
    }
    const ehplmnText = (s.ehplmn && s.ehplmn.length)
        ? s.ehplmn.map((p) => p.mcc + '-' + p.mnc).join(', ')
        : 'Not available';
    row(st, 'EHPLMN', ehplmnText);
    detailBody.appendChild(st);

    detailBody.appendChild(el('div', {text: 'ARA-M access rules', class: 'section-title'}));
    if (s.aram_rules === null || s.aram_rules === undefined) {
      detailBody.appendChild(el('p', {text: 'Not available (no ARA-M applet on this card)', class: 'muted'}));
    } else if (s.aram_rules.length === 0) {
      detailBody.appendChild(el('p', {text: 'No access rules configured', class: 'muted'}));
    } else {
      s.aram_rules.forEach((rule, i) => {
        detailBody.appendChild(el('div', {text: 'Rule ' + (i + 1), class: 'section-title'}));
        const rt = el('table');
        if (rule.package) row(rt, 'Package', rule.package);
        row(rt, 'AID', rule.aid || 'Not available');
        row(rt, 'Certificate hash', rule.device_app_id || 'Not available');
        row(rt, 'Android permissions', rule.android_permissions || 'Not available');
        detailBody.appendChild(rt);
      });
    }
  }
}

async function selectFile(path, labelEl, force) {
  if (selectedLabel) selectedLabel.classList.remove('selected');
  labelEl.classList.add('selected');
  selectedLabel = labelEl;
  currentPath = path;
  reloadButton.disabled = false;

  detailTitle.textContent = path;
  detailDesc.textContent = '';
  detailBody.textContent = '';
  detailBody.appendChild(el('p', {text: force ? 'Reloading...' : 'Reading...', class: 'muted'}));

  try {
    let url = '/api/read?path=' + encodeURIComponent(path);
    if (force) url += '&force=1';
    const res = await fetch(url, {cache: 'no-store'});
    const data = await res.json();
    // A file that doesn't actually exist on this card (as opposed to e.g. an ADM-protected
    // file that exists but failed to read) gets struck through in the tree.
    labelEl.classList.toggle('missing', !data.exists);
    detailDesc.textContent = data.desc || '';
    renderFileContent(data);
  } catch (e) {
    detailBody.textContent = '';
    detailBody.appendChild(el('p', {text: 'Request failed: ' + e, class: 'error'}));
  }
}

reloadButton.addEventListener('click', () => {
  // Force a fresh read from the card, bypassing the server-side content cache -- this must
  // work even for an item that previously failed to read (e.g. an ADM-protected file, or a
  // one-off transient error), so it's driven off currentPath/selectedLabel rather than
  // data.exists/data.error from the last read.
  if (currentPath && selectedLabel) {
    selectFile(currentPath, selectedLabel, true);
  }
});

async function fetchChildren(path) {
  if (treeCache.has(path)) return treeCache.get(path);
  const res = await fetch('/api/tree?path=' + encodeURIComponent(path), {cache: 'no-store'});
  const data = await res.json();
  treeCache.set(path, data);
  return data;
}

async function loadChildren(path, ul) {
  ul.textContent = '';
  ul.appendChild(el('li', {text: 'Loading...', class: 'tree-empty'}));
  let data;
  try {
    data = await fetchChildren(path);
  } catch (e) {
    ul.textContent = '';
    ul.appendChild(el('li', {text: 'Request failed: ' + e, class: 'tree-error'}));
    return;
  }
  const parentLabel = labelsByPath.get(path);
  if (parentLabel) parentLabel.classList.toggle('missing', !data.exists);

  ul.textContent = '';
  if (!data.exists) {
    ul.appendChild(el('li', {text: data.error || 'Not present on this card', class: 'tree-error'}));
    return;
  }
  if (data.children.length === 0) {
    ul.appendChild(el('li', {text: '(empty)', class: 'tree-empty'}));
    return;
  }
  for (const child of data.children) {
    const childPath = path + '/' + child.name;
    ul.appendChild(makeNode(child, childPath));
  }
}

function makeNode(info, path) {
  const li = el('li', {class: 'kind-' + info.kind});
  const label = el('span', {class: 'label'});
  const nameSpan = document.createTextNode(info.name + ' ');
  label.appendChild(nameSpan);
  if (info.fid) {
    label.appendChild(el('span', {text: '(' + info.fid + ')', class: 'fid'}));
  }
  if (info.desc) label.title = info.desc;
  li.appendChild(label);
  labelsByPath.set(path, label);

  // "special" applications (ARA-M, Security Domains like ISD, ...) don't provide regular
  // files -- pySim-shell exposes their content via application-specific commands instead of
  // file reads. Treat them as directly readable, like an EF, rather than as a directory to
  // expand (they have no meaningful children to browse). The synthetic "Summary" entry is
  // the same: not a real file, but directly readable.
  if (info.kind === 'ef' || info.kind === 'summary' || info.special) {
    label.classList.add('leaf');
    if (info.special) label.classList.add('special');
    label.addEventListener('click', () => selectFile(path, label));
  } else {
    label.classList.add('branch');
    const childUl = el('ul');
    childUl.style.display = 'none';
    li.appendChild(childUl);
    let loaded = false;
    label.addEventListener('click', async () => {
      const expanded = label.classList.toggle('expanded');
      childUl.style.display = expanded ? 'block' : 'none';
      if (expanded && !loaded) {
        loaded = true;
        await loadChildren(path, childUl);
      }
    });
  }
  return li;
}

async function loadRoot() {
  treeEl.textContent = '';
  treeCache.clear();
  labelsByPath.clear();

  // Synthetic entry (not a real file) showing the same overview card-summary.py prints --
  // must match the backend's card_browser.SUMMARY_PATH constant.
  const summaryInfo = {name: 'Summary', kind: 'summary', desc: 'Card identification and configuration summary'};
  treeEl.appendChild(makeNode(summaryInfo, 'Summary'));

  const rootLi = makeNode({name: 'MF', fid: '3f00', kind: 'mf'}, 'MF');
  treeEl.appendChild(rootLi);
  // Auto-expand the root once so the top-level tree is visible without an extra click --
  // this is still a single lazy fetch, not a recursive walk of the whole filesystem.
  rootLi.querySelector(':scope > .label').click();
}

function setAuthMsg(text, cls) {
  authMsg.textContent = text;
  authMsg.className = cls || '';
}

function setAdmVerified(verified) {
  admVerified = verified;
  authButton.textContent = verified ? 'Authenticated (ADM)' : 'Authenticate (ADM)';
  authButton.classList.toggle('authenticated', verified);
}

async function postVerifyAdm(body) {
  const res = await fetch('/api/verify_adm', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify(body),
  });
  return res.json();
}

async function onAuthSuccess(source) {
  setAdmVerified(true);
  authPanel.style.display = 'none';
  authPin.value = '';
  setAuthMsg('Authenticated (' + source + ')', 'success');
  // The server cleared its tree/content caches -- a file that previously failed with
  // "security status not satisfied" may now be readable, so re-fetch whatever is open.
  treeCache.clear();
  if (currentPath && selectedLabel) {
    await selectFile(currentPath, selectedLabel);
  }
}

authButton.addEventListener('click', async () => {
  authPanel.style.display = 'none';
  setAuthMsg('Trying ADM key database...', '');
  let result;
  try {
    result = await postVerifyAdm({});
  } catch (e) {
    setAuthMsg('Request failed: ' + e, 'failure');
    return;
  }
  if (result.ok) {
    await onAuthSuccess(result.source);
  } else if (result.need_pin) {
    setAuthMsg(result.error || 'Please enter a PIN', '');
    authPanel.style.display = 'flex';
    authPin.focus();
  } else {
    setAuthMsg(result.error || 'Authentication failed', 'failure');
  }
});

authCancel.addEventListener('click', () => {
  authPanel.style.display = 'none';
  authPin.value = '';
  setAuthMsg('', '');
});

authSubmit.addEventListener('click', async () => {
  const pin = authPin.value;
  if (!pin) {
    setAuthMsg('Please enter a PIN', 'failure');
    return;
  }
  setAuthMsg('Verifying...', '');
  let result;
  try {
    result = await postVerifyAdm({pin: pin, pin_is_hex: authHex.checked});
  } catch (e) {
    setAuthMsg('Request failed: ' + e, 'failure');
    return;
  }
  if (result.ok) {
    await onAuthSuccess(result.source);
  } else {
    setAuthMsg(result.error || 'Authentication failed', 'failure');
  }
});

authPin.addEventListener('keydown', (e) => {
  if (e.key === 'Enter') authSubmit.click();
});

async function pollCard() {
  let state;
  try {
    const res = await fetch('/api/card', {cache: 'no-store'});
    state = await res.json();
  } catch (e) {
    statusEl.textContent = 'disconnected';
    statusEl.className = 'status status-error';
    errorBox.style.display = 'block';
    errorBox.textContent = 'Lost connection to server: ' + e;
    return;
  }

  statusEl.textContent = state.status;
  statusEl.className = 'status status-' + state.status;

  if (state.error) {
    errorBox.style.display = 'block';
    errorBox.textContent = state.error;
  } else {
    errorBox.style.display = 'none';
  }

  const typeText = state.card_type
      ? (state.card_model ? state.card_type + ' (' + state.card_model + ')' : state.card_type)
      : null;
  cardinfoEl.textContent = typeText
      ? ('Card type: ' + typeText + '   ATR: ' + (state.atr || 'unknown'))
      : '';

  if (state.atr !== lastAtr) {
    // Card changed (or first load) -- the server-side caches were already reset; drop our
    // own tree/detail view and re-load the root from scratch. A new card starts out
    // unauthenticated regardless of whether the previous one was.
    lastAtr = state.atr;
    selectedLabel = null;
    currentPath = null;
    reloadButton.disabled = true;
    detailTitle.textContent = 'Select a file to view its contents';
    detailBody.textContent = '';
    authPanel.style.display = 'none';
    setAuthMsg('', '');
    if (state.status === 'ready') {
      loadRoot();
    } else {
      treeEl.textContent = '';
      treeCache.clear();
    }
  }

  setAdmVerified(!!state.adm_verified);
}

pollCard();
setInterval(pollCard, 2000);
"""


class Handler(BaseHTTPRequestHandler):
    monitor: CardMonitor = None  # set once in __main__ before the server starts
    session: CardSession = None
    server_version = 'card-browser-web/1.0'

    def log_message(self, format, *args):  # pylint: disable=redefined-builtin
        log.info("%s - %s", self.address_string(), format % args)

    def _send(self, status: int, content_type: str, body: bytes):
        self.send_response(status)
        self.send_header('Content-Type', content_type)
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Content-Security-Policy', "default-src 'self'")
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.end_headers()
        self.wfile.write(body)

    def _send_json(self, obj: dict):
        # Decoded card data can contain raw bytes/bytearray (e.g. some construct-based
        # decoders), which plain json.dumps() can't serialize -- reuse the same encoder
        # pySim-shell's own poutput_json() uses for exactly this.
        self._send(200, 'application/json', json.dumps(obj, cls=JsonEncoder).encode('utf-8'))

    def do_GET(self):
        parts = urlsplit(self.path)
        query = parse_qs(parts.query)

        if parts.path in ('/', '/index.html'):
            self._send(200, 'text/html; charset=utf-8', PAGE_HTML.encode('utf-8'))
        elif parts.path == '/style.css':
            self._send(200, 'text/css; charset=utf-8', PAGE_CSS.encode('utf-8'))
        elif parts.path == '/script.js':
            self._send(200, 'text/javascript; charset=utf-8', PAGE_JS.encode('utf-8'))
        elif parts.path == '/api/card':
            status = self.session.get_status()
            # The session may have invalidated itself (see CardSession._invalidate_removed())
            # in response to card I/O failing on some earlier, unrelated request -- reflect
            # that immediately rather than the monitor thread's last-known status, which only
            # updates on the *next* card-change event and would otherwise keep reporting
            # 'ready' for a card that's no longer there.
            status['status'] = 'error' if status['removed'] else self.monitor.status
            self._send_json(status)
        elif parts.path == '/api/tree':
            path = query.get('path', ['MF'])[0]
            self._send_json(self.session.list_children(path))
        elif parts.path == '/api/read':
            path = query.get('path', [None])[0]
            force = query.get('force', ['0'])[0] in ('1', 'true')
            if not path:
                self._send_json({'path': None, 'exists': False, 'error': "Missing 'path' query parameter"})
            else:
                self._send_json(self.session.read_file(path, force=force))
        else:
            self._send(404, 'text/plain; charset=utf-8', b'Not found')

    def do_POST(self):
        parts = urlsplit(self.path)

        if parts.path == '/api/verify_adm':
            length = int(self.headers.get('Content-Length', 0) or 0)
            raw_body = self.rfile.read(length) if length else b''
            try:
                body = json.loads(raw_body) if raw_body else {}
            except ValueError:
                self._send_json({'ok': False, 'error': 'Malformed JSON request body'})
                return
            result = self.session.verify_adm(pin=body.get('pin') or None,
                                             pin_is_hex=bool(body.get('pin_is_hex')),
                                             adm_type=body.get('adm_type') or None)
            self._send_json(result)
        else:
            self._send(404, 'text/plain; charset=utf-8', b'Not found')


if __name__ == '__main__':

    opts = option_parser.parse_args()

    PySimLogger.setup(print, {logging.WARN: "\033[33m"}, opts.verbose)

    # Init card key provider for automatic ADM key database lookup (used by verify_adm
    # when the user doesn't supply a PIN directly via the "Authenticate" button)
    card_key_provider_init(opts)

    sl = init_reader(opts)

    session = CardSession()
    monitor = CardMonitor(sl, session)
    monitor.start()

    Handler.monitor = monitor
    Handler.session = session
    server = ThreadingHTTPServer((opts.http_host, opts.http_port), Handler)
    print("Serving card browser on http://%s:%d/ (Ctrl-C to stop)" %
          (opts.http_host, opts.http_port))
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("")
        print("Terminated by user!")
    finally:
        server.server_close()
