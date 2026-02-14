#!/bin/sh

[ "$type" == "ip6tables" ] && exit 0   # check the protocol type in backward-compatible way
[ "$table" != "mangle" ] && exit 0   # check the table name

/opt/home/ndpi/ndpimarker-start.sh ipt_init
