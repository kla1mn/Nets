import struct
import random
import socket
import asyncio
import time
import json
import os

CACHE_FILE = "dns_cache.json"


class DNSHeader:
    def __init__(self):
        self.transaction_id = random.randint(0, 65535)
        self.flags = 0x0100
        self.qdcount = 1
        self.ancount = 0
        self.nscount = 0
        self.arcount = 0

    def create_header(self) -> bytes:
        header = struct.pack(">HHHHHH", self.transaction_id, self.flags,
                             self.qdcount, self.ancount, self.nscount, self.arcount)
        return header


class DNSQuestion:
    def __init__(self, domain, qtype=1, qclass=1):
        self.domain = domain
        self.qtype = qtype
        self.qclass = qclass

    def create_question(self):
        return self._encode_domain() + struct.pack(">HH", self.qtype, self.qclass)

    def _encode_domain(self):
        parts = self.domain.split(".")
        encoded_domain = b"".join((bytes([len(part)]) + part.encode() for part in parts))
        return encoded_domain + b"\x00"


class DNSPacket:
    def __init__(self, domain):
        self.header = DNSHeader()
        self.question = DNSQuestion(domain)

    def create_packet(self):
        return self.header.create_header() + self.question.create_question()


class DNSResolver:
    def __init__(self, server="8.8.8.8", port=53):
        self.server = server
        self.port = port
        self.cache = DNSCache()

    async def send_query(self, packet):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(5)
            sock.sendto(packet, (self.server, self.port))
            try:
                response = sock.recv(512)
                return response
            except socket.timeout:
                print("Request timed out")
                return None

    async def parse_response(self, response):
        if not response or len(response) < 12:
            return None

        header = response[:12]
        qdcount = struct.unpack(">H", header[4:6])[0]
        ancount = struct.unpack(">H", header[6:8])[0]

        offset = 12
        # Пропускаем вопросы
        for _ in range(qdcount):
            while offset < len(response) and response[offset] != 0:
                offset += 1
            offset += 5  # Пропускаем NULL-байт, qtype, qclass

        ip_addresses = []
        # Обрабатываем ответы
        for _ in range(ancount):
            if offset + 10 > len(response):  # Проверка, что достаточно байт для имени, типа и класса
                break

            offset += 2  # Пропускаем имя (ссылку на имя)
            rtype = struct.unpack(">H", response[offset:offset + 2])[0]
            rclass = struct.unpack(">H", response[offset + 2:offset + 4])[0]
            ttl = struct.unpack(">I", response[offset + 4:offset + 8])[0]
            rdlength = struct.unpack(">H", response[offset + 8:offset + 10])[0]
            offset += 10

            # Проверка, что оставшихся байт достаточно для rdata
            if offset + rdlength > len(response):
                break

            # Сохраняем только записи типа A (rtype == 1)
            if rtype == 1 and rdlength == 4:  # IPv4-адрес имеет длину 4 байта
                ip = response[offset:offset + 4]
                ip_addresses.append(".".join(map(str, ip)))
            offset += rdlength

        return ip_addresses if ip_addresses else None

    async def resolve(self, domain):
        # Проверка на .multiply.
        if ".multiply." in domain:
            ip_address = await self.handle_multiply(domain)
            return [ip_address]

        # Проверка кэша
        cached_ip = self.cache.get_value(domain)
        if cached_ip:
            print("Cache hit")
            return cached_ip
        print("Resolving", domain)
        packet = DNSPacket(domain).create_packet()
        response = await self.send_query(packet)

        ip_addresses = await self.parse_response(response)
        if ip_addresses:
            self.cache.add_value(domain, ip_addresses)
        return ip_addresses

    async def handle_multiply(self, domain) -> str:
        parts = domain.split(".")
        try:
            nums = [int(part) for part in parts if part.isdigit()]
            result = 1
            for num in nums:
                result = (result * num) % 256
            return f"127.0.0.{result}"
        except ValueError:
            return "127.0.0.1"


class DNSCache:
    def __init__(self):
        self.cache = self._load_cache()

    def _load_cache(self):
        if os.path.exists(CACHE_FILE):
            with open(CACHE_FILE, "r") as f:
                return json.load(f)
        return {}

    def _save_cache(self):
        with open(CACHE_FILE, "w") as f:
            json.dump(self.cache, f)

    def add_value(self, domain, ip_addresses, ttl=300):
        expire_time = time.time() + ttl
        self.cache[domain] = (ip_addresses, expire_time)
        self._save_cache()

    def get_value(self, domain):
        if domain in self.cache:
            ip_addresses, expire_time = self.cache[domain]
            if time.time() < expire_time:
                return ip_addresses
            else:
                del self.cache[domain]
                self._save_cache()
        return None


async def main():
    resolver = DNSResolver()
    print("Enter domain name or Q/Exit to exit.")

    while True:
        domain = input("Domain: ").strip()
        if domain.lower() in ["exit", "q"]:
            print("Exit")
            break

        ip_addresses = await resolver.resolve(domain)
        if ip_addresses:
            print(f"Resolved IPs for {domain}: {ip_addresses}")
        else:
            print(f"Can't resolve domain: {domain}")


if __name__ == "__main__":
    asyncio.run(main())
