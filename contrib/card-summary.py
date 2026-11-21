#!/usr/bin/env python3

# Utility to identify an inserted SIM/USIM card and print a short summary
# of its configuration (ICCID, IMSI, SPN, EHPLMN, ...).
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
import logging
import traceback
from pathlib import Path
from typing import Optional

from pySim.transport import init_reader, argparse_add_reader_args, LinkBase
from pySim.card_key_provider import card_key_provider_argparse_add_args, card_key_provider_init
from pySim.card_summary import build_summary, UST_SERVICE_EHPLMN, UST_SERVICE_SUCI_PRIVACY, UST_SERVICE_SUCI_CALCULATION, SUCI_PROT_SCHEME_IDENTIFIERS
from pySim.exceptions import NoCardError
from pySim.log import PySimLogger

log = PySimLogger.get(Path(__file__).stem)

option_parser = argparse.ArgumentParser(
    description='Identify an inserted SIM/USIM card and print a summary of its configuration',
    formatter_class=argparse.ArgumentDefaultsHelpFormatter)
option_parser.add_argument("--verbose", help="Enable verbose logging", action='store_true', default=False)
option_parser.add_argument("--batch", dest="batch_mode", action='store_true', default=False,
                            help="Batch mode: repeatedly wait for a (new) card, print its summary, then "
                                 "wait for the next card (Ctrl-C to stop)")
argparse_add_reader_args(option_parser)
card_key_provider_argparse_add_args(option_parser)


def format_plmn_list(plmns: Optional[list]) -> str:
    """Format a decoded EF_PLMNsel-style list of {'mcc', 'mnc'} entries."""
    if not plmns:
        return "\tNot available"
    return "\n".join("\tMCC: %s MNC: %s" % (p['mcc'], p['mnc']) for p in plmns)


def enabled_str(enabled: Optional[bool]) -> str:
    """Human-readable status of an EF.UST service (True/False/unknown)."""
    if enabled is None:
        return "unknown (EF.UST not readable)"
    return "enabled" if enabled else "disabled"


def print_summary(sl: LinkBase) -> bool:
    """Detect the card currently connected via 'sl', print a summary of its configuration.
    Returns True if a full summary could be printed."""

    data = build_summary(sl)

    print("Card type: %s" % (data['card_type'],))
    print("ATR:       %s" % (data['atr'],))

    if data['error']:
        print("\n%s" % (data['error'],))
        return False

    if data['applications']:
        print("Applications:")
        for app in data['applications']:
            print("  %s (%s)" % (app['aid'], app['name']))
    print()

    print("ICCID: %s" % (data['iccid'] or "Not available"))

    if data['iccid']:
        adm_known = data['adm_known']
        if adm_known is None:
            print("ADM key database: not configured (no --csv/--pgsql file found)")
        elif adm_known:
            print("ADM key database: card is known (ADM1 key on record)")
        else:
            print("ADM key database: card is NOT known (no ADM1 key on record for this ICCID)")
    else:
        print("ADM key database: Skipped (ICCID not available)")

    print("IMSI:  %s" % (data['imsi'] or "Not available"))

    spn = data['spn']
    if spn:
        print("SPN:   %s (show in HPLMN: %s, hide in OPLMN: %s)" %
              (spn['name'] or "Not available", spn['show_in_hplmn'], spn['hide_in_oplmn']))
    else:
        print("SPN:   Not available")

    print("EHPLMN (EF.UST service %d: %s):" % (UST_SERVICE_EHPLMN, enabled_str(data.get('ehplmn_service_enabled'))))
    print(format_plmn_list(data['ehplmn']))

    print()
    print("SUCI (subscriber identifier encryption):")
    suci = data.get('suci')
    if suci is None:
        print("\tNot available (no USIM application on this card)")
    else:
        print("\tSubscription identifier privacy (EF.UST service %d): %s" %
              (UST_SERVICE_SUCI_PRIVACY, enabled_str(suci['privacy_service_enabled'])))
        print("\tSUCI calculation by the USIM (EF.UST service %d): %s" %
              (UST_SERVICE_SUCI_CALCULATION, enabled_str(suci['calculation_service_enabled'])))
        for scheme in suci.get('prot_scheme_id_list') or []:
            print("\tProtection scheme (priority %s): %s, key %s" %
                  (scheme.get('priority'), SUCI_PROT_SCHEME_IDENTIFIERS.get(scheme.get('identifier'), 'unknown'),
                   scheme.get('key_index')))
        keys = suci.get('hnet_pubkeys') or []
        if keys:
            print("\tHome network public keys (EF.SUCI_Calc_Info):")
            for key in keys:
                print("\t\tIdentifier %s: %s" % (key['hnet_pubkey_identifier'], key['hnet_pubkey'] or "Not available"))
        else:
            print("\tHome network public keys (EF.SUCI_Calc_Info): Not available")

    print()
    print("ARA-M access rules:")
    aram_rules = data['aram_rules']
    if aram_rules is None:
        print("\tNot available (no ARA-M applet on this card)")
    elif not aram_rules:
        print("\tNo access rules configured")
    else:
        for i, rule in enumerate(aram_rules, 1):
            print("\tRule %d:" % (i,))
            if rule['package']:
                print("\t\tPackage:             %s" % (rule['package'],))
            print("\t\tAID:                 %s" % (rule['aid'] or "Not available"))
            print("\t\tCertificate hash:    %s" % (rule['device_app_id'] or "Not available"))
            print("\t\tAndroid permissions: %s" % (rule['android_permissions'] or "Not available"))

    return True


if __name__ == '__main__':

    opts = option_parser.parse_args()

    PySimLogger.setup(print, {logging.WARN: "\033[33m"}, opts.verbose)

    # Init card key provider for automatic ADM key database lookup
    card_key_provider_init(opts)

    sl = init_reader(opts)

    first = True
    while True:
        print("Insert card now (or Ctrl-C to cancel)" if first else
              "Remove card and insert next card (or Ctrl-C to stop)")
        try:
            sl.wait_for_card(newcardonly=not first)
        except (KeyboardInterrupt, NoCardError):
            # Some transports (e.g. PC/SC via pyscard) catch Ctrl-C internally while
            # blocked waiting for a card, cancel the pending request and raise a
            # (Card)RequestTimeoutException instead of letting KeyboardInterrupt
            # propagate. Since we always wait without a timeout, a NoCardError here
            # can only be the result of such a cancellation.
            print("")
            print("Terminated by user!")
            raise SystemExit(0)
        first = False

        try:
            ok = print_summary(sl)
        except KeyboardInterrupt:
            raise
        except Exception:
            print("Reading card failed with an exception:")
            print("---------------------8<---------------------")
            traceback.print_exc()
            print("---------------------8<---------------------")
            ok = False

        if not opts.batch_mode:
            raise SystemExit(0 if ok else 1)

        print()
