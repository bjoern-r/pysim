# -*- coding: utf-8 -*-

"""Build a structured summary of an inserted SIM/USIM card's configuration
(ICCID, IMSI, SPN, EHPLMN, ARA-M access rules, ADM key database status, ...).

This module contains no I/O beyond talking to the card and the configured ADM
key database -- it returns plain data structures. It is shared by the CLI tool
(card-summary.py) and the web variant (card-summary-web.py), which render the
same data differently (text vs. HTML/JSON).
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

from typing import Optional

from pySim.transport import LinkBase
from pySim.app import init_card
from pySim.runtime import RuntimeLchan
from pySim.ara_m import ADF_ARAM
from pySim.card_key_provider import card_key_provider_get_field, card_key_providers
from pySim.exceptions import SwMatchError
from pySim.log import PySimLogger

log = PySimLogger.get(__name__)


def read_ef(lchan: RuntimeLchan, path: str) -> Optional[dict]:
    """Select an EF by its absolute path (e.g. 'MF/EF.ICCID') and return its decoded
    content, or None if the file doesn't exist / can't be read on this card."""
    try:
        lchan.select(path)
    except Exception:
        return None
    try:
        data, sw = lchan.read_binary_dec()
    except Exception as e:
        log.warning("%s: Can't read file -- %s", path, e)
        return None
    if sw != '9000':
        log.warning("%s: Can't read, response code = %s", path, sw)
        return None
    return data


def get_from_do_list(key: str, do_list: Optional[list]):
    """pySim's GlobalPlatform/ARA-M TLV_IE_Collection.to_dict() output represents a group of
    Data Objects as a list of single-key dicts. Return the value for 'key', or None if absent."""
    for d in do_list or []:
        if key in d:
            return d[key]
    return None


def read_aram_rules(lchan: RuntimeLchan) -> Optional[list]:
    """Select the ARA-M applet (if present on this card) and retrieve all of its access
    control rules via GET DATA [All]. Returns a list of decoded rule dicts (each with
    'aid', 'package', 'device_app_id' i.e. the certificate hash, and 'android_permissions'),
    an empty list if ARA-M is present but has no rules stored, or None if there is no ARA-M
    applet on this card."""
    try:
        lchan.select('MF/ADF.ARA-M')
    except Exception:
        return None

    try:
        res_do = ADF_ARAM.get_all(lchan.scc)
    except SwMatchError as e:
        # "Referenced data not found" / "Incorrect values" -- ARA-M present, but empty
        if e.sw_actual in ('6a88', '6a80'):
            return []
        log.warning("ARA-M: Can't read access rules -- %s", e)
        return None
    except Exception as e:
        log.warning("ARA-M: Can't read access rules -- %s", e)
        return None
    if not res_do:
        return []

    rules = []
    for entry in res_do.to_dict():
        for ref_ar_do_entry in entry.get('response_all_ref_ar_do') or []:
            ref_ar_do = ref_ar_do_entry.get('ref_ar_do')
            if not ref_ar_do:
                continue
            ref_do = get_from_do_list('ref_do', ref_ar_do)
            ar_do = get_from_do_list('ar_do', ref_ar_do)
            aid = get_from_do_list('aid_ref_do', ref_do)
            if not aid and any('aid_ref_empty_do' in d for d in ref_do or []):
                aid = '(any/currently selected application)'
            pkg_ref = get_from_do_list('pkg_ref_do', ref_do)
            perm_ar_do = get_from_do_list('perm_ar_do', ar_do)
            rules.append({
                'aid': aid,
                'package': (pkg_ref or {}).get('package_name_string'),
                # GPD_SPE_013 Device-App-ID-REF-DO: SHA-1/SHA-256 hash of the app's signing
                # certificate (or a UUID) -- this is the "certificate hash" of the rule.
                'device_app_id': get_from_do_list('dev_app_id_ref_do', ref_do),
                # Android UICC Carrier Privileges extension: 8-byte permission bitmask
                'android_permissions': (perm_ar_do or {}).get('permissions'),
            })
    return rules


def check_adm_known(iccid: str) -> Optional[bool]:
    """Check whether an ADM1 key is on record for this card's ICCID in the configured ADM
    key database(s) (CSV/PostgreSQL), the same lookup pySim-shell's 'verify_adm' command
    uses to find a key automatically. This only checks the database -- it does not perform
    an actual VERIFY CHV against the card. Returns True/False, or None if no key provider
    is configured at all (no --csv/--pgsql file present)."""
    if not card_key_providers:
        return None
    try:
        result = card_key_provider_get_field('ADM1', key='ICCID', value=iccid)
    except ValueError:
        return False
    return result is not None


def build_summary(sl: LinkBase) -> dict:
    """Detect the card currently connected via 'sl' and return a structured summary of its
    configuration. Performs no output/rendering -- callers turn this into text, HTML, etc.

    Returned dict always has 'card_type' and 'atr'. If 'error' is set, the profile could not
    be detected and no further fields are populated. Otherwise 'applications', 'iccid',
    'adm_known', 'imsi', 'spn', 'ehplmn' and 'aram_rules' are populated (some possibly None/
    empty if not present/readable on this card).
    """
    # Detect the card and set up its filesystem/profile model, just like pySim-shell does
    rs, card = init_card(sl)
    return build_summary_from_rs(rs, card)


def build_summary_from_rs(rs, card) -> dict:
    """Same as build_summary(), but for a card whose RuntimeState/profile has already been
    detected (e.g. by pySim.card_browser.CardSession) -- avoids re-running init_card() (a
    full new profile/application detection cycle) just to build a summary of a card that's
    already been detected."""
    result = {
        'card_type': None,
        'atr': None,
        'error': None,
        'applications': [],
        'iccid': None,
        'adm_known': None,
        'imsi': None,
        'spn': None,
        'ehplmn': [],
        'aram_rules': None,
    }

    result['card_type'] = card.name
    result['atr'] = (rs.identity['ATR'] if rs else card._scc.get_atr()).lower()

    if rs is None:
        result['error'] = 'Card profile could not be detected -- unable to read further card contents.'
        return result

    if rs.mf.applications:
        result['applications'] = [{'aid': aid, 'name': adf.name or 'unknown'}
                                  for aid, adf in rs.mf.applications.items()]

    lchan = rs.lchan[0]

    iccid = read_ef(lchan, 'MF/EF.ICCID')
    result['iccid'] = iccid['iccid'] if iccid else None

    if result['iccid']:
        result['adm_known'] = check_adm_known(result['iccid'])

    # IMSI/SPN live under ADF.USIM on a UICC with a USIM application, or under the
    # legacy DF.GSM on a classic (2G-only) SIM. EHPLMN is USIM-specific.
    selectables = rs.mf.get_selectables()
    if 'ADF.USIM' in selectables:
        imsi_path, spn_path, ehplmn_path = 'MF/ADF.USIM/EF.IMSI', 'MF/ADF.USIM/EF.SPN', 'MF/ADF.USIM/EF.EHPLMN'
    elif 'DF.GSM' in selectables:
        imsi_path, spn_path, ehplmn_path = 'MF/DF.GSM/EF.IMSI', 'MF/DF.GSM/EF.SPN', None
    else:
        imsi_path = spn_path = ehplmn_path = None

    imsi = read_ef(lchan, imsi_path) if imsi_path else None
    result['imsi'] = imsi['imsi'] if imsi else None

    spn = read_ef(lchan, spn_path) if spn_path else None
    if spn:
        result['spn'] = {'name': spn['spn'], 'show_in_hplmn': spn['show_in_hplmn'],
                         'hide_in_oplmn': spn['hide_in_oplmn']}

    ehplmn = read_ef(lchan, ehplmn_path) if ehplmn_path else None
    if ehplmn is not None:
        result['ehplmn'] = [p for p in ehplmn if p]

    result['aram_rules'] = read_aram_rules(lchan)

    return result
