# Aeronautical Wireshark Plugin

## License

Aeronautical Wireshark Plugin

Copyright (C) 2023 Airbus CyberSecurity SAS

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.

### Third-party software usage

This program uses the following software to run:

| Software | Version | Copyright | License |
|-|-|-|-|
| Lua Bit Operations Module (Lua BitOp) | 1.0.2^ | 2008-2012 Mike Pall | MIT |
| Wireshark | 4.2.5^ | 1998-2023 Gerald Combs and contributors | GPL-2.0-or-later |

See repositories of third-party softwares for more information about their
dependencies.

## Introduction

`aeronautical-wireshark-plugin` provides an Arinc429 and discrete dissector for **Wireshark**.
Submitted PCAPNG files must use Link Layer 147 (USER_DLT0) with Enhanced Packet Block for Arinc429 and Link Layer 148 (USER_DLT1) with Enhanced Packet Block for discrete.

Protocol name: `a429` for Arinc429 and `discrete` for discrete.

## Dependencies

`aeronautical-wireshark-plugin` requires:

* `wireshark` with `lua 5.2` support enabled (wireshark < 4.3)
* Lua module `bitop` for Arinc429 support (provided as bit.dll in the windows build)
  * Installation on `ubuntu`:
  ~~~
  sudo apt-get install lua-bitop
  ~~~
  * Installation with `luarocks`:
  ~~~
  luarocks install luabitop
  ~~~

## Installing plugin

### From system plugins directory

The `a429` and `discrete` dissector will then be automatically loaded when starting wireshark, for all users, with the mapping active. `user_dlts` file in `/usr/share/wireshark` might be overwritten if you have your own one.

The extraction of the plugin in the system folders will most likely require root or admin rights.

#### On ubuntu (and other debian derivatives)

~~~
unzip `Wireshark_plugin-ubuntu.zip` -d /usr
~~~

#### On linux with standard HFS in /usr with `lib` and `share` directories (archlinux, alpine)

~~~
unzip `Wireshark_plugin-standard.zip` -d /usr
~~~

#### RedHat derivatives (RHEL, Almalinux, CentOS, Fedora, AmazonLinux)

Most of RHEL derivatives provides Wireshark without Lua. In this case re-compiling Wireshark with Lua support might be needed, as well as Lua 5.2 and LuaBitOp library (Fedora does provide wireshark with Lua support, and LuaBitOp automatically installed). If installed this way, wireshark configuration is often placed in `/usr/local`, so extracting it there instead of `/usr` should be done.

~~~
unzip `Wireshark_plugin-centos.zip` -d /usr
~~~

#### On Windows, with wireshark installed in its standard path:

Unzip `Wireshark_plugin-windows.zip` dissector to directory:

~~~
Expand-Archive Wireshark_plugin.zip ${ENV:PROGRAMFILES} -Force
~~~

The **-Force** option will update previously installed plugins, but will also overwrite custom user_dlts you might have customized.

The `a429` and `discrete` dissector will then be automatically loaded when starting wireshark, for all users, with the mapping active. `user_dlts` file in `/${ENV:PROGRAMFILES}\Wireshark` might be overwritten if you have your own one.

If wireshark is not installed in the standard path, extract the plugin in the Wireshark folder (user_dlts and bit.dll in this folder - alongside Wireshark.exe - and all other files in the `plugins` subfolder)

#### On MacOS, with wireshark recompiled with Lua support:

`brew` version does not come with lua, and if you compile from source it would be installed in `/usr/local`:

~~~
unzip `Wireshark_plugin-macos.zip` -d /usr/local
~~~

## Filtering capabilities

* As timestamps are set in the fields of the Enhanced Packet Block, all standard time filtering provided by `wireshark` are supported
* The `a429` dissector provides the following filtering keys:
  * `A429.WORD`: Filters on word value (hexadecimal)
  * `A429.LABEL`: Filters on label value (octal)
  * `A429.SDI`, `A429.SSM`, `A429.DATA`, `A429.PARITY`: Filters on fields value (hexadecimal)

For example, to filter on a label value:

~~~
A429.LABEL eq 0300
~~~

* The `discrete` dissector provides the following filtering keys:
  * `DISCRETE.VALUE`: Filters on data value (hexadecimal)

## Current limitations

* Length column displays the size of the packet_data field, and not of an ARINC429 word (4 bytes). Workaround: stop displaying the `Length` column (Edit `Column preferences`)
