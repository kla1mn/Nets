import random
import string
import struct

# from enum import IntEnum
#
#
# class QR(IntEnum):
#     Query = 0
#     Response = 1
#
#
# class Opcode(IntEnum):
#     StandardQuery = 0
#     InverseQuery = 1
#     ServerStatus = 2
#
#
# print(int.to_bytes(Opcode.StandardQuery), type(Opcode.StandardQuery.value))


"""
FLAGS
QR: 0 - query(request), 1 - response (1 bit)
OPCODE: - request type - 0 - standard query, 1 - inverse query, 2 - server status, 3..15 - for future (4 bit)
AA: 0 - not authoritative answer, 1 - authoritative answer (1 bit)
TC: truncated - 0 - not, 1 - truncated (1 bit)
RD: recursion desired - 0 - not, 1 - recursion desired (1 bit)
RA: recursion available - 0 - not, 1 - recursion desired (1 bit)
Z: for future - 0 (1 bit)
RCODE: status - 0 if success, else ... (4 bit)
"""


class DNSHeader:
    def __init__(self, **kwargs):
        self.id: int = self._generate_id()
        self.flags: int = 0
        self.qd_count: int = 0
        self.an_count: int = 0
        self.ns_count: int = 0
        self.ar_count: int = 0

    @staticmethod
    def _generate_id() -> int:
        return random.randint(0, 2 ** 16)

    def get_bytes_header(self) -> bytes:
        return struct.pack('!HHHHHH',
                           self.id, self.flags, self.qd_count, self.an_count, self.ns_count, self.ar_count)

    def __str__(self):
        return f"{self.id}{self.flags}{self.qd_count}{self.an_count}{self.ns_count}{self.ar_count}"


class DNSQuestion:
    def __init__(self):
        self.name: bytes
        self.type_: int
        self.class_: int


if __name__ == '__main__':
    header = DNSHeader(flags=1)
    print(header)
    print(header.get_bytes_header())
