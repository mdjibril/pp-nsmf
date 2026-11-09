#!/usr/bin/env python3
"""Minimal DNS responder for the PP-NSMF lab.

Listens on 10.10.10.40:53 (the Zeek monitor) and answers every A-record query
with 10.10.10.20 (the server), mirroring the previously observed responder
behaviour for the S2 scenario.

This file is version-controlled on the host so the responder can be redeployed
after a container recreation. Deploy to the Zeek node and run inside it:

    docker cp scripts/dns_responder.py <zeek_container>:/tmp/dns_responder.py
    docker exec -d <zeek_container> python3 /tmp/dns_responder.py
"""

import socket
import struct

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind(("10.10.10.40", 53))
print("DNS responder listening on 10.10.10.40:53", flush=True)

while True:
    data, addr = sock.recvfrom(2048)
    if len(data) < 17:
        continue

    pos = 12
    while pos < len(data) and data[pos] != 0:
        pos += data[pos] + 1
    pos += 5

    if pos > len(data):
        continue

    question = data[12:pos]
    header = data[:2] + struct.pack("!HHHHH", 0x8180, 1, 1, 0, 0)
    answer = b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 60, 4) + bytes([10, 10, 10, 20])

    sock.sendto(header + question + answer, addr)
    print("Answered DNS query from", addr, flush=True)
