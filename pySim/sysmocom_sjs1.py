# coding=utf-8
"""Utilities / Functions related to sysmocom SJS1 cards

(C) 2021-2023 by Harald Welte <laforge@osmocom.org>
(C) 2025 by Bjoern Riemer <bjoern.c3@nixda.biz>

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 2 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
"""

from struct import unpack
from construct import FlagsEnum, Byte, Struct, Int8ub, Mapping, Enum, Padding, BitsInteger
from construct import Bit, this, Int32ub, Int16ub, Nibble, BytesInteger, GreedyRange, Const
from construct import Optional as COptional
from osmocom.utils import *
from osmocom.construct import *

from pySim.filesystem import *
from pySim.runtime import RuntimeState
import pySim


class DF_AUTH(CardDF):
    def __init__(self):
        super().__init__(fid='7fcc', name='DF.AUTH', desc='CardOS specifics (SysmocomSJS1)')
        files = [
            EF_AUTH(),
            EF_MLNGC()
        ]
        self.add_files(files)

    def decode_select_response(self, resp_hex):
        return pySim.ts_102_221.CardProfileUICC.decode_select_response(resp_hex)


class EF_AUTH(TransparentEF):
    def __init__(self, fid='6f00', name='EF.AUTH', desc='Authentication parameters'):
        super().__init__(fid, name=name, desc=desc)
        self._construct = Struct('2G'/Enum(Byte, milenage=1, comp128v1=3, comp128v2=6, comp128v3=7, xor2g=4),
                                 '3G'/Enum(Byte, milenage=1, comp128v1=3, comp128v2=6, comp128v3=7, xor3g=8))


class EF_MLNGC(TransparentEF):
    _test_de_encode = [
        ( '00000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000200000000000000000000000000000004000000000000000000000000000000084000204060',
          {"c1": h2b("00000000000000000000000000000000"),
           "c2": h2b("00000000000000000000000000000001"),
           "c3": h2b("00000000000000000000000000000002"),
           "c4": h2b("00000000000000000000000000000004"),
           "c5": h2b("00000000000000000000000000000008"),
           "r1": 64, "r2": 0, "r3": 32, "r4": 64, "r5": 96
           } ),
      ]
    def __init__(self, fid='6f01', name='EF.MLNGC', desc='Milenage connfiguration'):
        super().__init__(fid, name=name, desc=desc)
        self._construct = Struct('c1'/Bytes(16),
                                 'c2'/Bytes(16),
                                 'c3'/Bytes(16),
                                 'c4'/Bytes(16),
                                 'c5'/Bytes(16),
                                 'r1'/Int8ub, 'r2'/Int8ub, 'r3'/Int8ub, 'r4'/Int8ub, 'r5'/Int8ub)


class EF_OPC_OP(TransparentEF):
    _test_de_encode = [
        ( '01d9342893eccdfc830526be5b19537a95',
          {"cfg": {"use_opc_instead_of_op": True},
           "op_opc": h2b("d9342893eccdfc830526be5b19537a95")} ),
      ]
    def __init__(self, fid='00f7', name='EF.OPC_OP'):
        super().__init__(fid, name=name, desc='OPC or OP')
        CfgByte = BitStruct(Padding(7),
                            'use_opc_instead_of_op'/Flag)
        self._construct = Struct('cfg'/CfgByte,
                                 'op_opc' /Bytes(16))


class EF_USIM_SQNA(TransparentEF):
    _test_de_encode = [
        ( '0000000000000000000004c00000000000c0000000000000000000000520000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000',
          {"freshness": [0, 1216, 192, 0, 1312, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]} ),
      ]
    def __init__(self, fid='00fa', name='EF.SQNA'):
        super().__init__(fid, name=name, desc='SQN Array')
        self._construct = Struct('freshness'/GreedyRange(BytesInteger(6)))


class EF_USIM_SQNC(TransparentEF):
    def __init__(self, fid='00fb', name='EF.SQNC'):
        super().__init__(fid, name=name, desc='SQN parameters for AKA')
        Flag1 = BitStruct('rfu'/BitsRFU(1), 'delta_max_check'/Flag,
                          'age_limit_check'/Flag, 'sqn_check'/Flag,
                          'ind_len'/BitsInteger(4))
        self._construct = Struct('flag1'/Flag1,
                                 'sqnms_offset'/BytesInteger(2), # divide by 6 ???
                                 'delta_max' /BytesInteger(6), # wrong value 8589934592 vs 268435456 -> original tool does >>5
                                 'age_limit'/BytesInteger(6)) # wrong value 8589934592 vs 268435456 -> original tool does >>5


class SysmocomSJS1(CardModel):
    _atrs = ["3B9F96801FC78031A073BE21136743200718000001A5"]

    @classmethod
    def add_files(cls, rs: RuntimeState):
        rs.mf.add_file(DF_AUTH())
        # extra files in DF_GSM
        df_gsm = rs.mf.children['7f20']
        df_gsm_files = [
            TransparentEF('00ff', None, 'EF.Ki', desc='Ki in proprietary file'),
            EF_OPC_OP()
        ]
        df_gsm.add_files(df_gsm_files)
        # optional USIM application
        if 'a0000000871002' in rs.mf.applications:
            usim_adf = rs.mf.applications['a0000000871002']
            files_adf_usim = [
                EF_USIM_SQNA(),
                EF_USIM_SQNC(),
            ]
            usim_adf.add_files(files_adf_usim)