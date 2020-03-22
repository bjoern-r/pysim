#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Various constants from ETSI TS 131 102
"""

#
# Copyright (C) 2020 Supreeth Herle <herlesupreeth@gmail.com>
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
#

# Mapping between USIM Service Number and its description
EF_UST_map = {
	1: 'Local Phone Book',
	2: 'Fixed Dialling Numbers (FDN)',
	3: 'Extension 2',
	4: 'Service Dialling Numbers (SDN)',
	5: 'Extension3',
	6: 'Barred Dialling Numbers (BDN)',
	7: 'Extension4',
	8: 'Outgoing Call Information (OCI and OCT)',
	9: 'Incoming Call Information (ICI and ICT)',
	10: 'Short Message Storage (SMS)',
	11: 'Short Message Status Reports (SMSR)',
	12: 'Short Message Service Parameters (SMSP)',
	13: 'Advice of Charge (AoC)',
	14: 'Capability Configuration Parameters 2 (CCP2)',
	15: 'Cell Broadcast Message Identifier',
	16: 'Cell Broadcast Message Identifier Ranges',
	17: 'Group Identifier Level 1',
	18: 'Group Identifier Level 2',
	19: 'Service Provider Name',
	20: 'User controlled PLMN selector with Access Technology',
	21: 'MSISDN',
	22: 'Image (IMG)',
	23: 'Support of Localised Service Areas (SoLSA)',
	24: 'Enhanced Multi-Level Precedence and Pre-emption Service',
	25: 'Automatic Answer for eMLPP',
	26: 'RFU',
	27: 'GSM Access',
	28: 'Data download via SMS-PP',
	29: 'Data download via SMS-CB',
	30: 'Call Control by USIM',
	31: 'MO-SMS Control by USIM',
	32: 'RUN AT COMMAND command',
	33: 'shall be set to 1',
	34: 'Enabled Services Table',
	35: 'APN Control List (ACL)',
	36: 'Depersonalisation Control Keys',
	37: 'Co-operative Network List',
	38: 'GSM security context',
	39: 'CPBCCH Information',
	40: 'Investigation Scan',
	41: 'MexE',
	42: 'Operator controlled PLMN selector with Access Technology',
	43: 'HPLMN selector with Access Technology',
	44: 'Extension 5',
	45: 'PLMN Network Name',
	46: 'Operator PLMN List',
	47: 'Mailbox Dialling Numbers',
	48: 'Message Waiting Indication Status',
	49: 'Call Forwarding Indication Status',
	50: 'Reserved and shall be ignored',
	51: 'Service Provider Display Information',
	52: 'Multimedia Messaging Service (MMS)',
	53: 'Extension 8',
	54: 'Call control on GPRS by USIM',
	55: 'MMS User Connectivity Parameters',
	56: 'Network\'s indication of alerting in the MS (NIA)',
	57: 'VGCS Group Identifier List (EFVGCS and EFVGCSS)',
	58: 'VBS Group Identifier List (EFVBS and EFVBSS)',
	59: 'Pseudonym',
	60: 'User Controlled PLMN selector for I-WLAN access',
	61: 'Operator Controlled PLMN selector for I-WLAN access',
	62: 'User controlled WSID list',
	63: 'Operator controlled WSID list',
	64: 'VGCS security',
	65: 'VBS security',
	66: 'WLAN Reauthentication Identity',
	67: 'Multimedia Messages Storage',
	68: 'Generic Bootstrapping Architecture (GBA)',
	69: 'MBMS security',
	70: 'Data download via USSD and USSD application mode',
	71: 'Equivalent HPLMN',
	72: 'Additional TERMINAL PROFILE after UICC activation',
	73: 'Equivalent HPLMN Presentation Indication',
	74: 'Last RPLMN Selection Indication',
	75: 'OMA BCAST Smart Card Profile',
	76: 'GBA-based Local Key Establishment Mechanism',
	77: 'Terminal Applications',
	78: 'Service Provider Name Icon',
	79: 'PLMN Network Name Icon',
	80: 'Connectivity Parameters for USIM IP connections',
	81: 'Home I-WLAN Specific Identifier List',
	82: 'I-WLAN Equivalent HPLMN Presentation Indication',
	83: 'I-WLAN HPLMN Priority Indication',
	84: 'I-WLAN Last Registered PLMN',
	85: 'EPS Mobility Management Information',
	86: 'Allowed CSG Lists and corresponding indications',
	87: 'Call control on EPS PDN connection by USIM',
	88: 'HPLMN Direct Access',
	89: 'eCall Data',
	90: 'Operator CSG Lists and corresponding indications',
	91: 'Support for SM-over-IP',
	92: 'Support of CSG Display Control',
	93: 'Communication Control for IMS by USIM',
	94: 'Extended Terminal Applications',
	95: 'Support of UICC access to IMS',
	96: 'Non-Access Stratum configuration by USIM',
	97: 'PWS configuration by USIM',
	98: 'RFU',
	99: 'URI support by UICC',
	100: 'Extended EARFCN support',
	101: 'ProSe',
	102: 'USAT Application Pairing',
	103: 'Media Type support',
	104: 'IMS call disconnection cause',
	105: 'URI support for MO SHORT MESSAGE CONTROL',
	106: 'ePDG configuration Information support',
	107: 'ePDG configuration Information configured',
	108: 'ACDC support',
	109: 'MCPTT',
	110: 'ePDG configuration Information for Emergency Service support',
	111: 'ePDG configuration Information for Emergency Service configured',
}