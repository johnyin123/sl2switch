# sl2switch
	A Simple layer 2 multi-point VPN, transfer over tcp ssl.
	support ipv4/ipv6

Usage: ./sl2switch [-h?vpdnsCckt] [connect to peers]
          

Options:
  -?, -h, --help    show this help screen
  -v, --verbose     increase verbosity
  -p, --port        listen port
                    default: 8880
  -d, --devname     tun/tap device name
                    default: tunvpn0
  -n, --nodename    local node name
                    default: yinzh
  -s, --ifup        tun device ifup scripte
                    default: if-up
  -C, --ca          the ca chain file to use
                    default: ca
  -c, --cert        the client cert file to load
                    default: cert
  -k, --key         the the client key file to use
                    default: key
  -t, --interval    time interval(msec)
                    default: 1800000

 
