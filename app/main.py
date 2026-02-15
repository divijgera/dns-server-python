import socket
from dataclasses import dataclass

@dataclass
class DNSHeader:
    id: int
    qr: int
    opcode: int
    aa: int
    tc: int
    rd: int
    ra: int
    z: int
    rcode: int
    qdcount: int
    ancount: int
    nscount: int
    arcount: int

    def to_bytes(self) -> bytes:
        header = bytearray(12)
        header[0:2] = self.id.to_bytes(2, byteorder="big")
        header[2] = (self.qr << 7) | (self.opcode << 3) | (self.aa << 2) | (self.tc << 1) | self.rd
        header[3] = (self.ra << 7) | (self.z << 4) | self.rcode
        header[4:6] = self.qdcount.to_bytes(2, byteorder="big")
        header[6:8] = self.ancount.to_bytes(2, byteorder="big")
        header[8:10] = self.nscount.to_bytes(2, byteorder="big")
        header[10:12] = self.arcount.to_bytes(2, byteorder="big")
        return bytes(header)

@dataclass
class UDPMessage:
    headers: DNSHeader
    question: str = ""
    answer: str = ""
    authority: str = ""
    additional: str = ""

    def to_bytes(self) -> bytes:
        return self.headers.to_bytes()
    
    def generate_response(self) -> None:
        self.headers.id = 1234
        self.headers.qr = 1
        self.headers.opcode = 0
        self.headers.aa = 0
        self.headers.tc = 0
        self.headers.rd = 0
        self.headers.ra = 0
        self.headers.z = 0
        self.headers.rcode = 0
        self.headers.qdcount = 0
        self.headers.ancount = 0
        self.headers.nscount = 0
        self.headers.arcount = 0
        
        return self.to_bytes()

def extract_headers(header: bytes) -> DNSHeader:
    return DNSHeader(
        id=int.from_bytes(header[0:2], byteorder="big"),
        qr=(header[2] >> 7) & 0x1,
        opcode=(header[2] >> 3) & 0xF,
        aa=(header[2] >> 2) & 0x1,
        tc=(header[2] >> 1) & 0x1,
        rd=header[2] & 0x1,
        ra=(header[3] >> 7) & 0x1,
        z=(header[3] >> 4) & 0x7,
        rcode=header[3] & 0xF,
        qdcount=int.from_bytes(header[4:6], byteorder="big"),
        ancount=int.from_bytes(header[6:8], byteorder="big"),
        nscount=int.from_bytes(header[8:10], byteorder="big"),
        arcount=int.from_bytes(header[10:12], byteorder="big"),
    )

def parse_request(buf: bytes) -> UDPMessage:
    header = buf[:12]
    headers = extract_headers(header)

    return UDPMessage(
        headers=headers
    )


def main():

    udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_socket.bind(("127.0.0.1", 2053))
    
    while True:
        try:
            buf, source = udp_socket.recvfrom(512)
            request = parse_request(buf)
    
            response = request.generate_response()
    
            udp_socket.sendto(response, source)
        except Exception as e:
            print(f"Error receiving data: {e}")
            break


if __name__ == "__main__":
    main()
