import argparse
import sys
import time
import traceback
from enum import IntEnum
from random import randint
from socket import socket
import logging

from scapy.layers.inet import TCP, IP
from scapy.packet import Packet
from scapy.sendrecv import sr1, sr

TIMEOUT = 2
THREADS_NUMBER = 10

logging.basicConfig(level=logging.INFO)

reserved_ports = {
    7: "ECHO",
    53: "DNS",
    80: "HTTP"
}


class Responses(IntEnum):
    FILTERED = 0
    CLOSED = 1
    OPEN = 2
    ERROR = 3


class TcpFlags(IntEnum):
    SYNC_ACK = 0x12
    RST_PSH = 0x14


def main():
    parser = _construct_args_parser()
    args = parser.parse_args()

    ip_address = args.ip_address
    ports = args.ports
    timeout = args.timeout if args.timeout else TIMEOUT
    num_threads = args.num_threads if args.num_threads else THREADS_NUMBER
    guess = args.guess
    verbose = args.verbose

    tcp_ports, udp_ports = _get_tcp_and_udp_ports_sets(ports)

    _print_and_open_tcp_ports(guess, ip_address, tcp_ports, timeout, verbose)


def _construct_args_parser():
    parser = argparse.ArgumentParser(description="TCP/UDP Port Scanner")
    parser.add_argument("-t", "--timeout", type=int, default=TIMEOUT, help="IP address to scan")
    parser.add_argument("-j", "--num-threads", type=int, default=THREADS_NUMBER, help="Number of threads")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose mode")
    parser.add_argument("-g", "--guess", action="store_true", help="Protocol guessing")
    parser.add_argument('ip_address', help="IP address to scan")
    parser.add_argument("ports", nargs="+", help="Ports to scan")
    return parser


def _get_tcp_and_udp_ports_sets(ports):
    tcp_ports, udp_ports = set(), set()
    for port in ports:
        if 'tcp' in port:
            _parse_port(port, tcp_ports)
        elif 'udp' in port:
            _parse_port(port, udp_ports)
        else:
            print(f"Invalid port: {port}")
    return tcp_ports, udp_ports


def _parse_port(port, ports):
    parts = port[4:].split(",")
    for part in parts:
        if "-" in part:
            start, end = map(int, part.split("-"))
            ports.update(range(start, end + 1))
        elif part.isdigit():
            ports.add(int(part))


def _print_and_open_tcp_ports(guess, ip_address, tcp_ports, timeout, verbose):
    for port in tcp_ports:
        logging.debug(f"Scanning TCP port {port}")
        start = time.time()
        response = _handle_tcp_port(port, ip_address, timeout)
        time_ms = time.time() - start
        if response == Responses.OPEN:
            res = ["TCP", str(port)]
            if verbose:
                res.append(f"{time_ms:.2f}ms")
            if guess:
                res.append(reserved_ports.get(port, '-'))
            print(" ".join(res))


def _handle_tcp_port(dport, ip_address, timeout):
    ip = IP(dst=ip_address)
    port = TCP(dport=dport, flags="S")
    reset = TCP(dport=dport, flags="F")
    packet: Packet = ip / port
    reset_packet: Packet = ip / reset

    try:
        response = sr1(packet, retry=2, timeout=timeout, threaded=True, verbose=False)

        if not response:
            return Responses.FILTERED

        if response.haslayer(TCP):
            if response.getlayer(TCP).flags == TcpFlags.SYNC_ACK:
                sr1(reset_packet, timeout=timeout, verbose=False)
                return Responses.OPEN
            elif response.getlayer(TCP).flags == TcpFlags.RST_PSH:
                return Responses.CLOSED

    except Exception:
        return Responses.ERROR


if __name__ == "__main__":
    main()
