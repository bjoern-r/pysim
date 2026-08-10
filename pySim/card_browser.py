# -*- coding: utf-8 -*-

"""Lazy, cached, read-only browsing of a card's filesystem tree.

This is the backend for the web-based filesystem browser (card-browser-web.py).
It reuses the same primitives pySim-shell's per-file-type shell commands are built
from (RuntimeLchan.select_file/read_binary/read_record/retrieve_data, CardFile.
decode_hex/decode_record_hex, ...), just composed to avoid re-reading data twice
(raw + decode) and to cache results for the lifetime of the currently inserted card.
"""

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

import threading
from typing import Optional

from osmocom.utils import h2b
from osmocom.tlv import camel_to_snake

from pySim.transport import LinkBase
from pySim.app import init_card
from pySim.runtime import RuntimeLchan
from pySim.filesystem import (CardFile, CardDF, CardADF, CardMF, CyclicEF, LinFixedEF, BerTlvEF, TransparentEF,
                              CardModel)
from pySim.ts_102_221 import pin_names
from pySim.utils import sanitize_pin_adm
from pySim.card_key_provider import card_key_provider_get_field
from pySim.ara_m import ADF_ARAM
from pySim.global_platform import ADF_SD, DataCollection
from pySim.card_summary import read_aram_rules as summary_read_aram_rules, build_summary_from_rs
from pySim.exceptions import NoCardError
from pySim.log import PySimLogger

log = PySimLogger.get(__name__)

# Synthetic tree entry (not a real CardFile) that shows the same overview
# pySim-summary.py/pySim-summary-web.py print/display -- see CardSession.read_file().
SUMMARY_PATH = 'Summary'


def detect_card_model(card) -> Optional[str]:
    """Return the name of the vendor-specific CardModel that matches this card's ATR (e.g.
    'SysmocomSJA2'), or None if none of the known models match. This is the same ATR-based
    matching pySim.app.init_card() already performs internally (via
    CardModel.apply_matching_models) to add vendor-specific files -- it just isn't otherwise
    exposed anywhere on RuntimeState, so we redo the (cheap, side-effect-free) match here to
    show it. 'UICC'/'SIM' alone only tells you the generic card family, not the actual
    product -- this is the more specific "detected card type"."""
    for m in CardModel.__subclasses__():
        try:
            if m.match(card._scc):
                return m.__name__
        except Exception:
            log.warning("CardModel %s.match() raised an exception", m.__name__, exc_info=True)
    return None


def detect_special_kind(f: CardFile) -> Optional[str]:
    """Identify applications that -- on pySim-shell's side -- don't expose a normal file
    tree but instead provide their functionality via application-specific commands (e.g.
    ARA-M's GET DATA [All], or GlobalPlatform Security Domains' GET DATA/GET STATUS). Such
    applications are still selectable ADFs, just without meaningful child files, so the web
    browser treats them as directly "readable" (like an EF) rather than as a directory to
    explore."""
    if isinstance(f, ADF_ARAM):
        return 'ara_m'
    if isinstance(f, ADF_SD):  # covers ADF.ISD and any other Security Domain
        return 'isd'
    return None


def describe_file(name: str, f: CardFile) -> dict:
    """Describe a CardFile (as returned by get_selectables()) for the tree API -- purely
    from pySim's static, in-memory file-model knowledge, no card access involved."""
    if isinstance(f, CardADF):
        kind = 'adf'
    elif isinstance(f, CardMF):
        kind = 'mf'
    elif isinstance(f, CardDF):
        kind = 'df'
    else:
        kind = 'ef'

    info = {'name': name, 'fid': getattr(f, 'fid', None), 'kind': kind, 'desc': f.desc or ''}

    special = detect_special_kind(f)
    if special:
        info['special'] = special

    if kind == 'ef':
        if isinstance(f, CyclicEF):
            info['structure'] = 'cyclic'
        elif isinstance(f, LinFixedEF):
            info['structure'] = 'linear_fixed'
        elif isinstance(f, BerTlvEF):
            info['structure'] = 'ber_tlv'
        elif isinstance(f, TransparentEF):
            info['structure'] = 'transparent'
        else:
            info['structure'] = 'unknown'
    return info


def read_ef_content(lchan: RuntimeLchan, target: CardFile) -> dict:
    """Read the full content of the currently-selected EF 'target', as raw hex plus decoded
    data, using the same RuntimeLchan primitives pySim-shell's read_binary(_decoded)/
    read_record(s)(_decoded)/retrieve_data commands use. Reads each record/blob only once
    (decoding locally from the already-fetched raw bytes) rather than reading it twice
    the way the individual raw vs. decoded shell commands would."""

    if isinstance(target, LinFixedEF):  # covers CyclicEF too (subclass)
        num = lchan.selected_file_num_of_rec() or 0
        records = []
        for rec_nr in range(1, num + 1):
            raw, sw = lchan.read_record(rec_nr)
            rec = {'record_nr': rec_nr, 'raw': raw, 'sw': sw, 'decoded': None, 'decode_error': None}
            if sw == '9000':
                try:
                    rec['decoded'] = target.decode_record_hex(raw, rec_nr)
                except Exception as e:
                    rec['decode_error'] = str(e)
            records.append(rec)
        return {
            'structure': 'cyclic' if isinstance(target, CyclicEF) else 'linear_fixed',
            'num_records': num,
            'record_len': lchan.selected_file_record_len(),
            'records': records,
        }

    if isinstance(target, BerTlvEF):
        tags = lchan.retrieve_tags()
        entries = []
        for tag in tags:
            raw, sw = lchan.retrieve_data(tag)
            entries.append({'tag': '0x%02x' % tag, 'raw': raw, 'sw': sw})
        return {'structure': 'ber_tlv', 'tags': entries}

    if isinstance(target, TransparentEF):
        raw, sw = lchan.read_binary()
        result = {'structure': 'transparent', 'raw': raw, 'sw': sw, 'decoded': None, 'decode_error': None}
        if sw == '9000':
            try:
                result['decoded'] = target.decode_hex(raw)
            except Exception as e:
                result['decode_error'] = str(e)
        return result

    raise ValueError("File type %s is not a readable EF" % (type(target).__name__,))


def read_special_content(lchan: RuntimeLchan, special: str) -> dict:
    """Read the read-only content of a "special" application (see detect_special_kind()),
    using the currently-selected ADF. Mirrors the read-only subset of the application-
    specific shell commands (ara_m.py's ADF_ARAM.get_all(), global_platform's ADF_SD
    do_get_data) rather than any file-based read."""

    if special == 'ara_m':
        # Reuses pySim.card_summary's ARA-M reader (built on ADF_ARAM.get_all(), the same
        # GET DATA [All] pySim-shell's do_aram_get_all uses). It re-selects 'MF/ADF.ARA-M'
        # by its fixed, well-known absolute path itself, so it doesn't matter which path the
        # caller used to get here.
        rules = summary_read_aram_rules(lchan)
        return {'structure': 'ara_m_rules', 'rules': rules if rules is not None else []}

    if special == 'isd':
        # GlobalPlatform GET DATA for each well-known data object (ADF_SD.do_get_data, just
        # swept across every object pySim knows about instead of one at a time). Not every
        # card/tag combination is supported -- report per-object errors rather than failing
        # the whole read.
        objects = []
        for cls in DataCollection.possible_nested:
            name = camel_to_snake(cls.__name__)
            tag_str = '0x%x' % cls.tag
            try:
                data, sw = lchan.scc.get_data(tag=cls.tag, cla=0x80)
                if sw != '9000':
                    raise ValueError('Not available (SW %s)' % (sw,))
                ie = cls()
                ie.from_tlv(h2b(data))
                objects.append({'name': name, 'tag': tag_str, 'decoded': ie.to_dict(), 'error': None})
            except NoCardError:
                # The card itself is gone (as opposed to this one object just not being
                # supported) -- let CardSession notice and invalidate the session instead
                # of pointlessly re-trying every remaining object against a dead card.
                raise
            except Exception as e:
                objects.append({'name': name, 'tag': tag_str, 'decoded': None, 'error': str(e)})
        return {'structure': 'gp_data_objects', 'objects': objects}

    raise ValueError("Unknown special application kind '%s'" % (special,))


class CardSession:
    """Tracks the currently inserted card's runtime state plus tree/content caches. All
    access to the card (and to the fields below) is serialized through 'lock' -- talking to
    a smart card is inherently a one-thing-at-a-time affair, and a background thread swaps
    in a new RuntimeState whenever the card changes, which must not race with an in-flight
    HTTP request still using the old one."""

    def __init__(self):
        self.lock = threading.Lock()
        self.rs = None
        self.card = None
        self.card_type: Optional[str] = None
        self.card_model: Optional[str] = None
        self.atr: Optional[str] = None
        self.error: Optional[str] = None
        self.removed = False
        self._tree_cache = {}
        self._content_cache = {}

    def set_card(self, sl: LinkBase):
        """(Re-)detect the card currently connected via 'sl' and reset the caches. Must be
        called with 'lock' held and only after a (blocking, lock-free) wait_for_card()."""
        rs, card = init_card(sl)
        self.rs = rs
        self.card = card
        self.card_type = card.name
        self.card_model = detect_card_model(card)
        self.atr = (rs.identity['ATR'] if rs else card._scc.get_atr()).lower()
        self.error = None if rs else 'Card profile could not be detected -- unable to browse its filesystem.'
        self.removed = False
        self._clear_caches()

    def _clear_caches(self):
        self._tree_cache = {}
        self._content_cache = {}

    def _invalidate_removed(self, reason: str):
        """Called (with 'lock' already held) when card I/O fails because the card was
        physically pulled from the reader mid-operation. Drops the RuntimeState and clears
        the tree/content caches immediately, rather than waiting for the CardMonitor
        background thread to notice on its next (blocking) wait_for_card() call -- that
        only fires on the *next* card insertion, so without this, browsing (and even a
        fresh page load) would keep serving stale cached content from the card that's now
        gone. Cleared again by set_card() once a card is (re-)detected."""
        self.rs = None
        self.card = None
        self.card_type = None
        self.card_model = None
        self.atr = None
        self.error = reason
        self.removed = True
        self._clear_caches()

    def get_status(self) -> dict:
        with self.lock:
            return {
                'card_type': self.card_type,
                'card_model': self.card_model,
                'atr': self.atr,
                'error': self.error,
                'adm_verified': bool(self.rs and self.rs.adm_verified),
                'removed': self.removed,
            }

    def list_children(self, path: str) -> dict:
        with self.lock:
            cached = self._tree_cache.get(path)
            if cached is not None:
                return cached
            try:
                result = self._list_children_uncached(path)
            except NoCardError as e:
                # The card was physically removed while we were talking to it -- invalidate
                # the whole session (see _invalidate_removed()) instead of just reporting
                # this one path as failed.
                self._invalidate_removed(str(e))
                return {'path': path, 'exists': False, 'children': [], 'error': str(e)}
            self._tree_cache[path] = result
            return result

    def _list_children_uncached(self, path: str) -> dict:
        if self.rs is None:
            return {'path': path, 'exists': False, 'children': [], 'error': self.error or 'No card inserted'}

        lchan = self.rs.lchan[0]
        target = lchan.get_file_by_name(path)
        if target is None:
            return {'path': path, 'exists': False, 'children': [], 'error': 'Unknown path'}
        if not isinstance(target, CardDF):
            return {'path': path, 'exists': False, 'children': [], 'error': 'Not a directory'}

        try:
            lchan.select_file(target)
        except NoCardError:
            raise  # see list_children() -- must propagate, not turn into a per-path error
        except Exception as e:
            return {'path': path, 'exists': False, 'children': [], 'error': str(e)}

        children = [describe_file(name, f)
                   for name, f in sorted(target.get_selectables(flags=['FNAMES', 'ANAMES']).items())]
        return {'path': path, 'exists': True, 'children': children, 'error': None}

    def read_file(self, path: str, force: bool = False) -> dict:
        with self.lock:
            if not force:
                cached = self._content_cache.get(path)
                if cached is not None:
                    return cached
            try:
                if path == SUMMARY_PATH:
                    result = self._read_summary_uncached()
                else:
                    result = self._read_file_uncached(path)
            except NoCardError as e:
                # The card was physically removed while we were talking to it -- invalidate
                # the whole session (see _invalidate_removed()) instead of just reporting
                # this one path as failed.
                self._invalidate_removed(str(e))
                return {'path': path, 'exists': False, 'error': str(e)}
            # Don't cache a transient failure -- e.g. the same request racing a card swap --
            # only cache once we actually got a definitive answer (found+read, or genuinely
            # not present/not a file).
            self._content_cache[path] = result
            return result

    def _read_summary_uncached(self) -> dict:
        """Build the same card summary pySim-summary.py prints (ICCID/IMSI/SPN/EHPLMN/ARA-M/
        ADM-key-database status), reusing the already-detected RuntimeState/card instead of
        re-running init_card() (which build_summary() would otherwise do)."""
        if self.rs is None:
            return {'path': SUMMARY_PATH, 'exists': False, 'error': self.error or 'No card inserted'}

        summary = build_summary_from_rs(self.rs, self.card)
        if summary.get('error'):
            return {'path': SUMMARY_PATH, 'exists': False, 'error': summary['error']}

        return {'path': SUMMARY_PATH, 'exists': True, 'error': None,
                'desc': 'Card identification and configuration summary',
                'structure': 'card_summary', 'summary': summary}

    def _read_file_uncached(self, path: str) -> dict:
        if self.rs is None:
            return {'path': path, 'exists': False, 'error': self.error or 'No card inserted'}

        lchan = self.rs.lchan[0]
        target = lchan.get_file_by_name(path)
        if target is None:
            return {'path': path, 'exists': False, 'error': 'Unknown path'}

        special = detect_special_kind(target)
        if special is None and isinstance(target, CardDF):
            return {'path': path, 'exists': False, 'error': 'This is a directory, not a file'}

        try:
            lchan.select_file(target)
        except NoCardError:
            raise  # see read_file() -- must propagate, not turn into a per-path error
        except Exception as e:
            return {'path': path, 'exists': False, 'error': str(e)}

        try:
            content = read_special_content(lchan, special) if special else read_ef_content(lchan, target)
        except NoCardError:
            raise  # see read_file() -- must propagate, not turn into a per-path error
        except Exception as e:
            return {'path': path, 'exists': True, 'desc': target.desc or '', 'error': str(e)}

        return {'path': path, 'exists': True, 'error': None, 'desc': target.desc or '', **content}

    def _get_iccid_locked(self) -> Optional[str]:
        """Return the card's ICCID, reading it (uncached path -- we already hold 'lock') if
        it hasn't been read yet. Used to look up an ADM key by ICCID in verify_adm()."""
        cached = self._content_cache.get('MF/EF.ICCID')
        if cached and cached.get('decoded'):
            return cached['decoded'].get('iccid')
        result = self._read_file_uncached('MF/EF.ICCID')
        self._content_cache['MF/EF.ICCID'] = result
        if result.get('decoded'):
            return result['decoded'].get('iccid')
        return None

    def verify_adm(self, pin: Optional[str] = None, pin_is_hex: bool = False,
                   adm_type: Optional[str] = None) -> dict:
        """Authenticate the current session with the card's ADM (Administrator) PIN, the same
        way pySim-shell's 'verify_adm' command does: if no PIN is given, look one up from the
        configured ADM key database (CSV/PostgreSQL) by ICCID. On success, clears the tree/
        content caches, since files that previously failed with "security status not
        satisfied" may now be readable (and vice versa is not a concern -- ADM verification
        cannot be un-done for the session)."""
        with self.lock:
            if self.rs is None:
                return {'ok': False, 'error': self.error or 'No card inserted'}

            try:
                return self._verify_adm_locked(pin, pin_is_hex, adm_type)
            except NoCardError as e:
                # The card was physically removed while we were talking to it -- invalidate
                # the whole session (see _invalidate_removed()) instead of just reporting
                # this one request as failed.
                self._invalidate_removed(str(e))
                return {'ok': False, 'error': str(e)}

    def _verify_adm_locked(self, pin: Optional[str], pin_is_hex: bool,
                           adm_type: Optional[str]) -> dict:
        """The actual body of verify_adm() -- split out so a NoCardError raised anywhere in
        here (including via _get_iccid_locked()) is caught in exactly one place by its
        caller, rather than needing a try/except at every card-access point below."""
        if adm_type:
            if adm_type not in pin_names.inverse:
                return {'ok': False, 'error': "Unknown adm_type '%s'" % (adm_type,)}
            adm_chv_num = pin_names.inverse[adm_type]
        else:
            adm_chv_num = self.card._adm_chv_num

        if pin:
            try:
                pin_adm = sanitize_pin_adm(None, pin) if pin_is_hex else sanitize_pin_adm(pin)
            except ValueError as e:
                return {'ok': False, 'error': str(e)}
            source = 'user-provided PIN'
        else:
            lookup_type = adm_type or 'ADM1'
            iccid = self._get_iccid_locked()
            if not iccid:
                return {'ok': False, 'need_pin': True,
                        'error': 'Could not determine ICCID to look up an ADM key -- please enter a PIN'}
            try:
                found = card_key_provider_get_field(lookup_type, key='ICCID', value=iccid)
            except ValueError:
                found = None
            if not found:
                return {'ok': False, 'need_pin': True,
                        'error': "No %s key on record for ICCID '%s' -- please enter a PIN" %
                                (lookup_type, iccid)}
            try:
                pin_adm = sanitize_pin_adm(None, found) if len(found) > 8 else sanitize_pin_adm(found)
            except ValueError as e:
                return {'ok': False, 'error': str(e)}
            source = "%s from ADM key database (ICCID %s)" % (lookup_type, iccid)

        try:
            self.rs.lchan[0].scc.verify_chv(adm_chv_num, h2b(pin_adm))
        except NoCardError:
            raise  # see verify_adm() -- must propagate, not turn into a per-request error
        except Exception as e:
            return {'ok': False, 'error': str(e)}

        self.rs.adm_verified = True
        self._clear_caches()
        return {'ok': True, 'source': source}
