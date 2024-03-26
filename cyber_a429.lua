-- This file is part of Aeronautical Wireshark Plugin.
--
-- Copyright (C) 2023 Airbus CyberSecurity SAS
--
-- Aeronautical Wireshark Plugin is free software: you can redistribute it
-- and/or modify it under the terms of the GNU General Public License as
-- published by the Free Software Foundation, either version 3 of the License,
-- or (at your option) any later version.
--
-- Aeronautical Wireshark Plugin is distributed in the hope that it will be
-- useful, but WITHOUT ANY WARRANTY; without even the implied warranty of
-- MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General
-- Public License for more details.
--
-- You should have received a copy of the GNU General Public License along with
-- Aeronautical Wireshark Plugin. If not, see <https://www.gnu.org/licenses/>.

a429_protocol = Proto("a429", "ARINC 429")
WORD = ProtoField.uint32("A429.WORD","Word value", base.HEX)
LABEL = ProtoField.uint8("A429.LABEL","Label", base.OCT)
SDI = ProtoField.uint8("A429.SDI","SDI", base.HEX)
SSM = ProtoField.uint8("A429.SSM","SSM", base.HEX)
DATA = ProtoField.uint32("A429.DATA","Data", base.HEX)
PARITY = ProtoField.uint8("A429.PARITY","Parity", base.DEC)
a429_protocol.fields = {WORD, LABEL, SDI, SSM, DATA, PARITY}

function _get_string_length(buffer, start, max)
    local string_length = 0
    for i = start, max - 1, 1 do
        if (buffer(i,1):le_uint() == 0) then
            -- +1 to include the \0
            string_length = i - start + 1
            break
        end
    end
    return string_length
end

function _create_word_subtree(buffer, tree)
    local broadcast_word_subtree = tree:add(a429_protocol, buffer(), "Broadcast word")

    local word = buffer(0,4):uint()
    broadcast_word_subtree:add(WORD, word)

    local bit = require("bit")

    local label_byte = bit.band(word, 0xff)
    label_byte = bit.bor(bit.rshift(bit.band(label_byte, bit.lshift(1, 7)), 7),
                         bit.rshift(bit.band(label_byte, bit.lshift(1, 6)), 5),
                         bit.rshift(bit.band(label_byte, bit.lshift(1, 5)), 3),
                         bit.rshift(bit.band(label_byte, bit.lshift(1, 4)), 1),
                         bit.lshift(bit.band(label_byte, bit.lshift(1, 3)), 1),
                         bit.lshift(bit.band(label_byte, bit.lshift(1, 2)), 3),
                         bit.lshift(bit.band(label_byte, bit.lshift(1, 1)), 5),
                         bit.lshift(bit.band(label_byte, 1), 7))
    broadcast_word_subtree:add(LABEL, label_byte)

    local sdi = bit.rshift(word, 8)
    sdi = bit.band(sdi, 3)
    broadcast_word_subtree:add(SDI, sdi)

    local ssm = bit.rshift(word, 29)
    ssm = bit.band(ssm, 3)
    broadcast_word_subtree:add(SSM, ssm)

    local data = bit.rshift(word, 10)
    data = bit.band(data, 0x3ffff)
    broadcast_word_subtree:add(DATA, data)

    local parity = bit.rshift(word, 31)
    parity = bit.band(parity, 1)
    broadcast_word_subtree:add(PARITY, parity)
end

function _set_source_column_value(buffer, offset, pinfo, tree)
    local buffer_length = buffer:len()
    local channel_name_length = _get_string_length(buffer, offset, buffer_length)
    local channel_name = buffer(offset, channel_name_length)
    pinfo.cols.src = channel_name:string()
end

function a429_protocol.dissector(buffer, pinfo, tree)
    pinfo.cols.protocol = a429_protocol.name

    _set_source_column_value(buffer, 4, pinfo, tree)

    _create_word_subtree(buffer, tree)
end
