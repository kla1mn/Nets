import socket
import struct

from math import prod
from typing import Any, Optional


class DNSServer:
    def __init__(self):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.bind(('0.0.0.0', 53))
        self.root_server = "192.203.230.10"  # e.root-servers.net

    def process(self) -> None:
        while True:
            data, addr = self.socket.recvfrom(512)
            response = self._process_query(data)
            self.socket.sendto(response, addr)

    def _process_query(self, data: bytes) -> bytes:
        header, question = self._parse_query(data)
        domain = self._get_domain_from_bytes(question)
        if 'multiply' in domain:
            return self._handle_multiply(domain, header[0])
        response = self._resolve(data, self.root_server)
        return response if response else self._generate_error_response(header[0])

    def _handle_multiply(self, domain: str, id: int) -> bytes:
        parts = domain.split('.')
        numbers = [int(part) for part in parts if part.isdigit()]
        result = prod(numbers) % 256
        return self._generate_response(id, domain, f'127.0.0.{result}')

    def _resolve(self, query: bytes, server: str) -> Optional[bytes]:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.sendto(query, (server, 53))
            s.settimeout(5)
            response = s.recv(512)
        header = struct.unpack('!6H', response[:12])
        if header[3] > 0:
            return response
        elif header[4] > 0:
            next_server = self._get_next_server(response)
            if next_server:
                return self._resolve(query, next_server)
        return None

    def _generate_response(self, id: int, domain: str, ip: str) -> bytes:
        header = struct.pack('!6H', id, 0x8180, 1, 1, 0, 0)
        question = self._domain_to_question(domain) + struct.pack('!2H', 1, 1)
        answer = self._domain_to_question(domain) + struct.pack('!HHIH', 1, 1, 60, 4) + socket.inet_aton(ip)
        return header + question + answer

    def _generate_error_response(self, id: int) -> bytes:
        return (struct.pack('!6H', id, 0x8183, 1, 0, 0, 0)
                + self._domain_to_question("error.local") + struct.pack('!2H', 1, 1))

    @staticmethod
    def _parse_query(data: bytes) -> tuple[tuple[Any, ...], int | bytes]:
        header = struct.unpack('!6H', data[:12])
        question = data[12:]
        return header, question

    @staticmethod
    def _get_domain_from_bytes(data: bytes) -> str:
        parts, i = [], 0
        while i < len(data):
            length = data[i]
            if length == 0:
                break
            parts.append(data[i + 1: i + 1 + length].decode())
            i += length + 1
        return '.'.join(parts)

    @staticmethod
    def _get_next_server(data: bytes) -> Optional[str]:
        offset = 12
        questions = struct.unpack('!H', data[4:6])[0]
        for _ in range(questions):
            while data[offset] != 0:
                offset += 1
            offset += 5
        additional_count = struct.unpack('!H', data[10:12])[0]
        for _ in range(additional_count):
            if data[offset:offset + 2] == b'\xc0\x0c':
                offset += 2
            else:
                while data[offset] != 0:
                    offset += 1
                offset += 1
            record_type = struct.unpack('!H', data[offset:offset + 2])[0]
            offset += 8
            data_length = struct.unpack('!H', data[offset:offset + 2])[0]
            offset += 2
            if record_type == 1:
                return socket.inet_ntoa(data[offset:offset + 4])
            offset += data_length
        return None

    @staticmethod
    def _domain_to_question(domain: str) -> bytes:
        return b''.join(struct.pack('B', len(part)) + part.encode() for part in domain.split('.')) + b'\x00'


if __name__ == "__main__":
    server = DNSServer()
    print(f"Start local dns server")
    server.process()
