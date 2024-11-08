import socket
import struct

from math import prod


class DNSServer:
    def __init__(self):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.bind(('0.0.0.0', 53))
        self.root_server = "198.41.0.4"  # a.root-servers.net

    def process(self):
        while True:
            data, addr = self.socket.recvfrom(512)
            response = self._process_query(data)
            self.socket.sendto(response, addr)

    def _process_query(self, data):
        header, question = self._parse_query(data)
        domain = self._bytes_to_domain(question)

        if 'multiply' in domain:
            return self._handle_multiply(domain, header[0])

        response = self._resolve(data, self.root_server)

        return response if response else self._create_error_response(header[0])

    def _parse_query(self, data):
        header = struct.unpack('!6H', data[:12])
        question = data[12:]
        return header, question

    def _bytes_to_domain(self, data):
        parts, i = [], 0
        while i < len(data):
            length = data[i]
            if length == 0:
                break
            parts.append(data[i + 1: i + 1 + length].decode())
            i += length + 1
        return '.'.join(parts)

    def _handle_multiply(self, domain, id):
        parts = domain.split('.')
        numbers = [int(part) for part in parts if part.isdigit()]
        result = prod(numbers) % 256
        return self._create_response(id, domain, f'127.0.0.{result}')

    def _resolve(self, query, server):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.sendto(query, (server, 53))
            s.settimeout(5)
            response = s.recv(512)

        header = struct.unpack('!6H', response[:12])
        if header[3] > 0:
            return response
        elif header[4] > 0:
            next_server = self._extract_next_server(response)
            if next_server:
                return self._resolve(query, next_server)
        return None

    def _extract_next_server(self, data):
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

    def _create_response(self, id, domain, ip):
        header = struct.pack('!6H', id, 0x8180, 1, 1, 0, 0)
        question = self._domain_to_question(domain) + struct.pack('!2H', 1, 1)
        answer = self._domain_to_question(domain) + struct.pack('!HHIH', 1, 1, 60, 4) + socket.inet_aton(ip)
        return header + question + answer

    def _create_error_response(self, id) -> bytes:
        return (struct.pack('!6H', id, 0x8183, 1, 0, 0, 0)
                + self._domain_to_question("error.local") + struct.pack('!2H', 1, 1))

    def _domain_to_question(self, domain) -> bytes:
        return b''.join(struct.pack('B', len(part)) + part.encode() for part in domain.split('.')) + b'\x00'


if __name__ == "__main__":
    server = DNSServer()
    print(f"Start local dns server")
    server.process()
