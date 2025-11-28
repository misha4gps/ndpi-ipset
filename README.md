ndpi-ipset
=========

A small Linux tool that uses nDPI to detect application/protocols from network flows
and (optionally) calls commands or manages an `ipset` based on detected traffic.

**Key ideas**
- **Capture**: reads raw packets from a network interface.
- **Detect**: uses `libndpi` to identify protocols and application names.
- **Act**: runs configured commands (format strings) when matching traffic is seen
  and can add/remove IPs using `libipset`.

**Files of interest**
- `ndpi-ipset.c` : main program source (capture, detection, ipset integration).
- `Makefile` : simple build (uses `gcc`, links against `libndpi` and `libipset`).
- `scripts/ndpi-ipset-start.sh` : example helper script for creating ipset, iptables rules
  and starting the daemon.

**Requirements**
- A Linux system with root privileges (raw sockets and ipset operations require root).
- `libndpi` and headers (development package) installed and available to linker.
- `libipset` (user-space library) and headers for ipset integration.
- `gcc`, `make`.

On some systems you may need to install packages like `libndpi-dev` and `libipset-dev`
or build and install `libndpi`/`libipset` from source. The `Makefile` will try
to pick up `/opt/lib/libipset.so*` or fall back to `-lipset`.

Build
-----
Run:

```bash
make
```

This produces the `ndpi-ipset` binary.

Usage
-----
```
./ndpi-ipset [interface] [proto_file|-] [add_line|-] [del_line|-] [internal_nets|-] [diag_ip|-] [ipset_name|-] [ipset_timeout|-]
```

- `interface`: network interface to capture (default `br0` if none provided).
- `proto_file`: path to a `proto.list` file. Use `-` to load `proto.list` next to the
  executable, or to use a small built-in default list when `proto.list` is not present.
  The file accepts one entry per line: either a numeric nDPI protocol id or an application
  name (substring). Lines beginning with `#` are treated as comments.
- `add_line`: command format string to execute when a matching flow is first detected.
- `del_line`: command format string to execute when a flow is removed/aged-out.
- `internal_nets`: comma-separated CIDR list (e.g. `192.168.0.0/24,10.0.0.0/8`) of
  networks to treat as internal (flows to those networks are ignored for marking).
- `diag_ip`: optional IP to use for diagnostic output in some modes.
- `ipset_name`: if provided, enables `libipset` integration and the program will attempt
  to add/delete IPs from the named ipset.
- `ipset_timeout`: timeout in seconds for entries added to the ipset (default: 3600 or
  fallback constant defined in source).

Placeholders for `add_line` / `del_line`
------------------------------------
These are ordinary `printf`-style format strings. When the program executes the
command it replaces the placeholders with flow values in this order:

1. destination IP (string)
2. destination port (int)
3. source IP (string)
4. source port (int)
5. protocol string (`tcp` or `udp`)

Example (only needs destination IP):

```bash
"ipset add vpn-ipset %s timeout 3600 --exist"
```

When `snprintf` is applied the first `%s` will be replaced with the destination IP.

proto.list format
-----------------
- Each non-empty, non-comment line is either a numeric ndpi protocol id or an
  application name (substring) to match against detected application name.
- Example entries:

```
# numeric ndpi protocol id
45

# application name substring
whatsapp
```

If you pass `-` for `proto_file` and no `proto.list` is found next to the binary,
the program includes a small built-in list (WhatsApp related protocols) as a
fallback.

Included example
----------------
This repository includes an example `proto.list` in the project root. It contains
numeric nDPI protocol ids (optionally with comments) and application name
substrings. Example contents:

```
# list id from /usr/include/ndpi/ndpi_protocol_ids.h

45	NDPI_PROTOCOL_WHATSAPP_CALL
142	NDPI_PROTOCOL_WHATSAPP	
242	NDPI_PROTOCOL_WHATSAPP_FILES

whatsapp
face
youtube
tls.microsoft
tls.llm
tls.azure
```

You can point the program at this file directly by passing `proto.list` as the
`proto_file` argument.

Example runs
------------

Build and run capturing on `eno1`, using an on-disk `proto.list`, and add matching
destination IPs to an ipset called `vpn-ipset`:

```bash
make
sudo ./ndpi-ipset eno1 proto.list "ipset add vpn-ipset %s timeout 3600 --exist" \
    "ipset del vpn-ipset %s" "192.168.0.0/24" "192.168.0.53"
```
or 
```bash
make
sudo ./ndpi-ipset eno1 proto.list - - "192.168.0.0/24" - vpn-ipset 3600
```

Use the provided helper script to set up ipset/iptables rules and run the detector:

```bash
sudo ./scripts/ndpi-ipset-start.sh start
```

Notes and tips
--------------
- Run as root (required). The program will exit if `getuid()` != 0.
- The project links against `libndpi` and `libipset` — ensure the libraries and
  header files are installed and visible to the compiler/linker.
- The `add_line`/`del_line` string is run as a command by the program; be careful
  with quoting and shell metacharacters. The program uses `posix_spawn` to execute
  commands split into argv; complex shell constructs should be run through a shell
  wrapper (e.g. `sh -c '... %s ...'`).

Tested On
---------
- **Ubuntu 24**: build and runtime verified.
- **Keenetic Viva (KN-1910)**: successfully tested for expected ipset/iptables
  interactions in target environment.

**License**: This project is licensed under the GNU General Public License v2 (or later).

See the top-level `LICENSE` file for the full text. SPDX identifier: `SPDX-License-Identifier: GPL-2.0-or-later`.
