#!/usr/bin/env python3

# Web variant of card-summary: runs a small local HTTP server that shows a
# live-updating summary of whatever SIM/USIM card is currently inserted, in a
# browser. Reuses the same pySim.card_summary logic as the text-mode tool.
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

from pySim.transport import init_reader, argparse_add_reader_args
from pySim.card_key_provider import card_key_provider_argparse_add_args, card_key_provider_init
from pySim.card_summary import build_summary
from pySim.log import PySimLogger

log = PySimLogger.get(Path(__file__).stem)

option_parser = argparse.ArgumentParser(
    description='Show a live-updating summary of the inserted SIM/USIM card on a local webpage',
    formatter_class=argparse.ArgumentDefaultsHelpFormatter)
option_parser.add_argument("--verbose", help="Enable verbose logging", action='store_true', default=False)
option_parser.add_argument("--http-host", default='127.0.0.1',
                            help="Address to bind the web server to (use 0.0.0.0 to allow access "
                                 "from other hosts on the network)")
option_parser.add_argument("--http-port", type=int, default=8000, help="TCP port for the web server")
argparse_add_reader_args(option_parser)
card_key_provider_argparse_add_args(option_parser)


class CardMonitor(threading.Thread):
    """Background thread that continuously waits for card insertions/re-insertions and keeps
    the latest summary available for the HTTP handler to serve. The card is only re-read when
    it actually changes (removed + (re-)inserted) -- the last successful summary keeps being
    served (as 'ready') while we block waiting for the next change."""

    def __init__(self, sl):
        super().__init__(daemon=True)
        self.sl = sl
        self._lock = threading.Lock()
        self._state = {'status': 'waiting', 'updated_at': time.time(), 'summary': None, 'message': None}

    def _set_state(self, status: str, summary=None, message=None):
        with self._lock:
            self._state = {'status': status, 'updated_at': time.time(), 'summary': summary, 'message': message}

    def get_state(self) -> dict:
        with self._lock:
            return dict(self._state)

    def run(self):
        first = True
        while True:
            try:
                self.sl.wait_for_card(newcardonly=not first)
            except Exception as e:
                # Note: this runs in a background thread, so Ctrl-C (SIGINT) is delivered to
                # the main thread (blocked in server.serve_forever()), never here -- any
                # exception here is a genuine reader/transport error, not a user cancellation.
                log.warning("wait_for_card failed: %s", e)
                time.sleep(1)
                continue
            first = False

            self._set_state('reading')
            try:
                summary = build_summary(self.sl)
            except Exception as e:
                log.exception("Failed to read card")
                self._set_state('error', message=str(e))
                continue

            if summary.get('error'):
                self._set_state('error', summary=summary, message=summary['error'])
            else:
                self._set_state('ready', summary=summary)


# Fully static page -- all dynamic data is fetched from /api/summary as JSON and rendered
# client-side using textContent (never innerHTML), so untrusted card content (SPN, package
# names, ...) can never be interpreted as HTML/script. CSS and JS are served as separate
# same-origin files (rather than inline) so the CSP below can forbid 'unsafe-inline'.
PAGE_HTML = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Card Summary</title>
<link rel="stylesheet" href="/style.css">
</head>
<body>
<h1>Card Summary <span id="status" class="status status-waiting">waiting</span></h1>
<div id="updated"></div>
<div id="error-box"></div>
<div id="content"></div>
<script src="/script.js"></script>
</body>
</html>
"""

PAGE_CSS = """
:root { color-scheme: light dark; }
body { font-family: system-ui, -apple-system, sans-serif; margin: 2rem auto; max-width: 900px;
      padding: 0 1rem; }
h1 { font-size: 1.4rem; display: flex; align-items: center; gap: 0.6rem; }
h2 { font-size: 1.05rem; margin: 1.2rem 0 0.3rem; }
.status { display: inline-block; padding: 0.15rem 0.6rem; border-radius: 999px;
         font-size: 0.8rem; font-weight: 600; }
.status-waiting { background: #e2e8f0; color: #334155; }
.status-reading { background: #fef3c7; color: #92400e; }
.status-ready   { background: #dcfce7; color: #166534; }
.status-error   { background: #fee2e2; color: #991b1b; }
table { border-collapse: collapse; width: 100%; margin: 0.4rem 0 1rem; }
th, td { text-align: left; padding: 0.3rem 0.6rem; border-bottom: 1px solid #e5e7eb;
        vertical-align: top; }
th { width: 12rem; color: #64748b; font-weight: 600; }
ul { margin: 0.2rem 0 1rem; padding-left: 1.4rem; }
.rule { border: 1px solid #e5e7eb; border-radius: 8px; padding: 0.6rem 0.8rem; margin-bottom: 0.6rem; }
.rule table { margin: 0.3rem 0 0; }
#updated { color: #64748b; font-size: 0.85rem; margin-bottom: 1rem; }
#error-box { display: none; background: #fee2e2; color: #991b1b; padding: 0.8rem;
            border-radius: 8px; margin-bottom: 1rem; white-space: pre-wrap; }
#content p { color: #64748b; }
"""

PAGE_JS = """
"use strict";

const statusEl = document.getElementById('status');
const updatedEl = document.getElementById('updated');
const errorBox = document.getElementById('error-box');
const content = document.getElementById('content');

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
  tr.appendChild(el('td', {text: value}));
  table.appendChild(tr);
}

function admText(adm_known) {
  if (adm_known === true) return 'Known (ADM1 key on record)';
  if (adm_known === false) return 'NOT known (no ADM1 key on record for this ICCID)';
  return 'Not configured (no ADM key database file found)';
}

function renderSummary(summary) {
  content.textContent = '';

  const t1 = el('table');
  row(t1, 'Card type', summary.card_type || 'Unknown');
  row(t1, 'ATR', summary.atr || 'Unknown');
  content.appendChild(t1);

  if (summary.applications && summary.applications.length) {
    content.appendChild(el('h2', {text: 'Applications'}));
    const ul = el('ul');
    for (const app of summary.applications) {
      ul.appendChild(el('li', {text: app.aid + ' (' + app.name + ')'}));
    }
    content.appendChild(ul);
  }

  const t2 = el('table');
  row(t2, 'ICCID', summary.iccid || 'Not available');
  row(t2, 'ADM key database', admText(summary.adm_known));
  row(t2, 'IMSI', summary.imsi || 'Not available');
  if (summary.spn) {
    row(t2, 'SPN', (summary.spn.name || 'Not available') +
        ' (show in HPLMN: ' + summary.spn.show_in_hplmn +
        ', hide in OPLMN: ' + summary.spn.hide_in_oplmn + ')');
  } else {
    row(t2, 'SPN', 'Not available');
  }
  const ehplmnText = (summary.ehplmn && summary.ehplmn.length)
      ? summary.ehplmn.map((p) => p.mcc + '-' + p.mnc).join(', ')
      : 'Not available';
  row(t2, 'EHPLMN', ehplmnText);
  content.appendChild(t2);

  content.appendChild(el('h2', {text: 'ARA-M access rules'}));
  if (summary.aram_rules === null || summary.aram_rules === undefined) {
    content.appendChild(el('p', {text: 'Not available (no ARA-M applet on this card)'}));
  } else if (summary.aram_rules.length === 0) {
    content.appendChild(el('p', {text: 'No access rules configured'}));
  } else {
    summary.aram_rules.forEach((rule, i) => {
      const div = el('div', {class: 'rule'});
      div.appendChild(el('strong', {text: 'Rule ' + (i + 1)}));
      const t = el('table');
      if (rule.package) row(t, 'Package', rule.package);
      row(t, 'AID', rule.aid || 'Not available');
      row(t, 'Certificate hash', rule.device_app_id || 'Not available');
      row(t, 'Android permissions', rule.android_permissions || 'Not available');
      div.appendChild(t);
      content.appendChild(div);
    });
  }
}

async function refresh() {
  let state;
  try {
    const res = await fetch('/api/summary', {cache: 'no-store'});
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
  updatedEl.textContent = 'Last updated: ' + new Date(state.updated_at * 1000).toLocaleString();

  if (state.status === 'error') {
    errorBox.style.display = 'block';
    errorBox.textContent = state.message || 'Unknown error';
  } else {
    errorBox.style.display = 'none';
  }

  if (state.summary) {
    renderSummary(state.summary);
  } else if (state.status === 'waiting') {
    content.textContent = '';
    content.appendChild(el('p', {text: 'Insert a SIM/USIM card into the reader...'}));
  } else if (state.status === 'reading') {
    content.textContent = '';
    content.appendChild(el('p', {text: 'Reading card...'}));
  }
}

refresh();
setInterval(refresh, 1500);
"""


class Handler(BaseHTTPRequestHandler):
    monitor: CardMonitor = None  # set once in __main__ before the server starts
    server_version = 'card-summary-web/1.0'

    def log_message(self, format, *args):  # pylint: disable=redefined-builtin
        log.info("%s - %s", self.address_string(), format % args)

    def _send(self, status: int, content_type: str, body: bytes):
        self.send_response(status)
        self.send_header('Content-Type', content_type)
        self.send_header('Content-Length', str(len(body)))
        # The page has no inline <script>/<style> (both are served as separate same-origin
        # files below), so this CSP can stay strict without needing 'unsafe-inline'.
        self.send_header('Content-Security-Policy', "default-src 'self'")
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path in ('/', '/index.html'):
            self._send(200, 'text/html; charset=utf-8', PAGE_HTML.encode('utf-8'))
        elif self.path == '/style.css':
            self._send(200, 'text/css; charset=utf-8', PAGE_CSS.encode('utf-8'))
        elif self.path == '/script.js':
            self._send(200, 'text/javascript; charset=utf-8', PAGE_JS.encode('utf-8'))
        elif self.path == '/api/summary':
            body = json.dumps(self.monitor.get_state()).encode('utf-8')
            self._send(200, 'application/json', body)
        else:
            self._send(404, 'text/plain; charset=utf-8', b'Not found')


if __name__ == '__main__':

    opts = option_parser.parse_args()

    PySimLogger.setup(print, {logging.WARN: "\033[33m"}, opts.verbose)

    # Init card key provider for automatic ADM key database lookup
    card_key_provider_init(opts)

    sl = init_reader(opts)

    monitor = CardMonitor(sl)
    monitor.start()

    Handler.monitor = monitor
    server = ThreadingHTTPServer((opts.http_host, opts.http_port), Handler)
    print("Serving card summary on http://%s:%d/ (Ctrl-C to stop)" %
          (opts.http_host, opts.http_port))
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("")
        print("Terminated by user!")
    finally:
        server.server_close()
