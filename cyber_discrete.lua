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

discrete_protocol = Proto("discrete", "DISCRETE")
VALUE = ProtoField.uint32("DISCRETE.VALUE","Value", base.HEX)
discrete_protocol.fields = {VALUE}

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

function _create_data_subtree(buffer, tree)
    local data_subtree = tree:add(discrete_protocol, buffer(), "Data")

    local value = buffer(0,4):uint()
    data_subtree:add(VALUE, value)
end

function _set_source_column_value(buffer, offset, pinfo)
    local buffer_length = buffer:len()
    local channel_name_length = _get_string_length(buffer, offset, buffer_length)
    local channel_name = buffer(offset, channel_name_length)

    pinfo.cols.src = channel_name:string()
end

function discrete_protocol.dissector(buffer, pinfo, tree)
    pinfo.cols.protocol = discrete_protocol.name

    _set_source_column_value(buffer, 4, pinfo)

    _create_data_subtree(buffer, tree)
end
