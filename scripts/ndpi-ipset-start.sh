#!/bin/sh
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

ndpi_init()
{

    #if ! grep -q "^321[[:space:]]\+rt_vpn$" /opt/etc/iproute2/rt_tables; then
    #    echo "321 rt_vpn" >> /opt/etc/iproute2/rt_tables
    #fi
    if ! ip route show table $RT_NAME | grep -q "^default dev $WG_INTERFACE"; then
        ip route add default dev $WG_INTERFACE table $RT_NAME
    fi
    if ! ip rule show | grep -q "fwmark $FW_MARK lookup $RT_NAME"; then
        ip rule add fwmark $FW_MARK table $RT_NAME
    fi

    ipset create $IPSET_NAME hash:ip timeout 0 -exist

    if ! iptables -t mangle -S PREROUTING | grep -q -- "--match-set $IPSET_NAME dst -j MARK --set-xmark $FW_MARK/0xffffffff"; then
        iptables -t mangle -A PREROUTING -m set --match-set $IPSET_NAME dst -j MARK --set-mark $FW_MARK
    fi
    #if ! iptables -t mangle -S OUTPUT | grep -q -- "--match-set $IPSET_NAME dst -j MARK --set-xmark $FW_MARK/0xffffffff"; then
    #    iptables -t mangle -A OUTPUT -m set --match-set $IPSET_NAME dst -j MARK --set-mark $FW_MARK
    #fi

    ip route flush cache
}

ndpi_export()
{
    export FW_MARK=0x10
    export WG_INTERFACE="nwg0"
    export RT_NAME=rt_vpn
    export IPSET_NAME=vpn-ipset

#    export interface="br0"
    export interface="eno1"
#    export proto_file="$SCRIPT_DIR/proto.list"
    export proto_file="-"
#    export add_line="ipset add $IPSET_NAME %s timeout 3600 --exist"
#    export del_line="ipset del $IPSET_NAME %s"
    export add_line="-"
    export del_line="-"
    #int_nets="192.168.0.0/16,176.106.169.50"
    export int_nets="192.168.0.0/24"
#    export ndpi_path="$SCRIPT_DIR/ndpimarker"
    export ndpiipset_path="ndpi-ipset"
}

ndpi_start()
{
    if [ -x "$ndpiipset_path" ]; then
        trap '' INT
#		valgrind --leak-check=full --leak-resolution=high --show-leak-kinds=all --track-origins=yes --dsymutil=yes --error-limit=no --verbose --log-file=/tmp/valgrind/dpimarker_%p \
#
        $SCRIPT_DIR/$ndpiipset_path "$interface" "$proto_file" "$add_line" "$del_line" "$int_nets" $IPSET_NAME
        trap - INT
    else
         echo "Error: $ndpiipset_path not found or not executable"
    fi
}

ndpi_clean()
{

    echo "clean iptables and ip rules"

    # Remove installed iptables rules
    iptables -t mangle -D OUTPUT -m set --match-set $IPSET_NAME dst -j MARK --set-mark $FW_MARK 2>/dev/null
    iptables -t mangle -D PREROUTING -m set --match-set $IPSET_NAME dst -j MARK --set-mark $FW_MARK 2>/dev/null

    # Remove ip rule
    while ip rule del from all fwmark $FW_MARK table $RT_NAME 2>/dev/null; do :; done

    # Remove route from rt_vpn table
    ip route del default dev $WG_INTERFACE table $RT_NAME 2>/dev/null

    # Remove ipset
    ipset destroy $IPSET_NAME 2>/dev/null

    ip route flush cache
}


case "$1" in
    init)
        ndpi_export
        ndpi_init
        ;;
    ndpi_export)
        ndpi_export
        ;;
    start)
        ndpi_export
        ndpi_start
        ;;
    clean)
        ndpi_export
        ndpi_clean
        ;;
    *)
        ndpi_export
        ndpi_init
        ndpi_start
        ndpi_clean
        ;;
esac
