import socket
import re
import time
import argparse
from ipaddress import ip_address
from scapy.all import sr1
from scapy.layers.inet import IP, ICMP, UDP, TCP

WHOIS_SERVERS = [("whois.arin.net", lambda ip: f"n + {ip}\r\n"), ("whois.apnic.net", lambda ip: f"-V Md5.5.7 {ip}\r\n")]


def traceroute(destination_ip, protocol, timeout=2, port=80, max_hops=30, verbose=False):
    dst_ip = ip_address(destination_ip)
    if dst_ip.version != 4:
        return

    ttl = 1
    hop_num = 1

    while ttl <= max_hops:
        start_time = time.time()

        response = send_packet(protocol, ttl, destination_ip, port, timeout)

        end_time = time.time()
        rtt = _get_rtt(start_time, end_time)

        if response is None:
            print(f"{hop_num} *")
        else:
            resp_ip = _get_ip_from_response(response)
            if _print_hop(hop_num, resp_ip, rtt, verbose, destination_ip):
                break

        ttl += 1
        hop_num += 1


def query_whois(ip_str):
    for server, query_func in WHOIS_SERVERS:
        try:
            asn = _do_whois_query(server, query_func(ip_str))
            if asn is not None:
                return asn
        except Exception:
            pass
    return None


def send_packet(protocol, ttl, destination_ip, port, timeout):
    ip_layer = IP(dst=destination_ip, ttl=ttl)

    if protocol == 'icmp':
        pkt = ip_layer / ICMP()
    elif protocol == 'udp':
        pkt = ip_layer / UDP(dport=port)
    elif protocol == 'tcp':
        pkt = ip_layer / TCP(dport=port, flags='S')
    else:
        return None

    try:
        return sr1(pkt, verbose=0, timeout=timeout)
    except Exception:
        return None


def _configurate_arg_parser():
    parser = argparse.ArgumentParser(description="Traceroute")
    parser.add_argument('dst', type=str, help='IP address')
    parser.add_argument('proto', type=str, choices=['icmp', 'tcp', 'udp'], help='Protocol')
    parser.add_argument('-t', type=float, default=2.0, help='Timeout in seconds')
    parser.add_argument('-p', type=int, default=80, help='Port')
    parser.add_argument('-n', type=int, default=50, help='Max number of hops')
    parser.add_argument('-v', action='store_true', help='AS number')
    return parser


def _do_whois_query(server, query):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(5)
    s.connect((server, 43))
    s.send(query.encode('utf-8'))

    response = b""
    while True:
        try:
            data = s.recv(4096)
            if not data:
                break
            response += data
        except socket.timeout:
            break
    s.close()
    text = response.decode('utf-8', errors='replace')
    match = re.search(r'AS(\d+)', text)
    if match:
        return match.group(1)
    return None


def _get_rtt(start_time, end_time):
    return (end_time - start_time) * 1000


def _get_ip_from_response(response):
    return response[IP].src if IP in response else "*"


def _print_hop(hop_num, resp_ip, rtt, verbose, destination_ip):
    as_str = ""
    if verbose and resp_ip != "*":
        asn = query_whois(resp_ip)
        if asn:
            as_str = f"[AS {asn}] "

    if resp_ip == "*":
        print(f"{hop_num} *")
    else:
        if verbose:
            print(f"{hop_num} {resp_ip} {as_str}[{int(rtt)}ms]")
        else:
            print(f"{hop_num} {resp_ip} [{int(rtt)}ms]")

    if resp_ip == destination_ip:
        return True
    return False


def main():
    parser = _configurate_arg_parser()
    args = parser.parse_args()
    traceroute(destination_ip=args.dst, protocol=args.proto, timeout=args.t,
               port=args.p, max_hops=args.n, verbose=args.v)


if __name__ == '__main__':
    main()
