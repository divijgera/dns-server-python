import socket
from dataclasses import dataclass
import argparse

IP_ADDRESS = "8.8.8.8"
TTL_SECONDS = 60

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
class DNSName:
    labels: list[str]

    def to_bytes(self) -> bytes:
        name_bytes = bytearray()
        for label in self.labels:
            name_bytes.append(len(label))
            name_bytes.extend(label.encode("utf-8"))
        name_bytes.append(0)
        return bytes(name_bytes)

@dataclass
class DNSQuestion:
    qname: DNSName
    qtype: int
    qclass: int

    def to_bytes(self) -> bytes:
        response = self.qname.to_bytes()
        response += self.qtype.to_bytes(2, byteorder="big")
        response += self.qclass.to_bytes(2, byteorder="big")

        return response
    
@dataclass
class ResourceRecord:
    name: DNSName
    type: int
    class_: int
    ttl: int
    rdata: bytes
    rdlength: int

    def to_bytes(self) -> bytes:
        response = self.name.to_bytes()
        response += self.type.to_bytes(2, byteorder="big")
        response += self.class_.to_bytes(2, byteorder="big")
        response += self.ttl.to_bytes(4, byteorder="big")
        response += self.rdlength.to_bytes(2, byteorder="big")
        response += self.rdata

        return response

@dataclass
class UDPMessage:
    headers: DNSHeader
    questions: list[DNSQuestion]
    answer: list[ResourceRecord]
    authority: str = ""
    additional: str = ""

    def to_bytes(
            self,
            headers: DNSHeader,
            questions: list[DNSQuestion],
            answer: list[ResourceRecord]
        ) -> bytes:
        response = headers.to_bytes()
        if questions:
            for question in questions:
                response += question.to_bytes()
        
        if answer:
            for record in answer:
                response += record.to_bytes()
    
        return response
    
    def generate_answers(self, questions: list[DNSQuestion]) -> list[ResourceRecord]:
        answer = []
        for question in questions:
            answer.append(
                ResourceRecord(
                    name=question.qname,
                    type=question.qtype,
                    class_=question.qclass,
                    ttl=TTL_SECONDS,
                    rdata=socket.inet_aton(IP_ADDRESS),
                    rdlength=4
                )
            )

        return answer
    
    def generate_response(self) -> bytes:
        answers = self.answer if self.answer else self.generate_answers(self.questions)

        response_headers = DNSHeader(
            id=self.headers.id,
            qr=1,
            opcode=self.headers.opcode,
            aa=0,
            tc=0,
            rd=self.headers.rd,
            ra=0,
            z=0,
            rcode=0 if self.headers.opcode == 0 else 4,
            qdcount=self.headers.qdcount,
            ancount=len(answers) if answers else 0,
            nscount=0,
            arcount=0,
        )
        
        return self.to_bytes(response_headers, self.questions, answers)
    
    def generate_resolver_reponse(self, ip: str, port: int) -> bytes:
        answers = []
        forward_header = DNSHeader(
            id=self.headers.id,
            qr=0,
            opcode=0,
            aa=0,
            tc=0,
            rd=1,
            ra=0,
            z=0,
            rcode=0,
            qdcount=1,
            ancount=0,
            nscount=0,
            arcount=0,
        )

        for question in self.questions:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.settimeout(5)
                forward_bytes = self.to_bytes(forward_header, [question], [])
                sock.sendto(forward_bytes, (ip, port))
                response_bytes, _ = sock.recvfrom(512)

                response_message = parse_request(response_bytes)
                if response_message.headers.rcode == 0 and response_message.answer:
                    answers.extend(response_message.answer)

        response_headers = DNSHeader(
            id=self.headers.id,
            qr=1,
            opcode=self.headers.opcode,
            aa=0,
            tc=0,
            rd=self.headers.rd,
            ra=0,
            z=0,
            rcode=0 if self.headers.opcode == 0 else 4,
            qdcount=self.headers.qdcount,
            ancount=len(answers) if answers else 0,
            nscount=0,
            arcount=0,
        )

        return self.to_bytes(response_headers, self.questions, answers)

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

def read_labels(buffer: bytes, offset: int) -> tuple[list[str], int]:
    labels = []
    next_offset = offset
    jumped = False
    seen_offsets = set()
    while True:
        if offset >= len(buffer):
            raise ValueError("Offset out of bounds")
        if offset in seen_offsets:
            raise ValueError("Loop detected in label pointers")
        seen_offsets.add(offset)

        length = buffer[offset]

        # Compression pointer: 11xxxxxx xxxxxxxx
        if (length & 0xC0) == 0xC0:
            if offset + 1 >= len(buffer):
                raise ValueError("Truncated compression pointer")
            pointer = ((length & 0x3F) << 8) | buffer[offset + 1]
            if not jumped:
                next_offset = offset + 2
                jumped = True
            offset = pointer
            continue

        # End of name
        if length == 0:
            if not jumped:
                next_offset = offset + 1
            break

        offset += 1
        if offset + length > len(buffer):
            raise ValueError("Truncated DNS label")
        labels.append(buffer[offset:offset + length].decode("utf-8"))
        offset += length

    return labels, next_offset

def extract_questions(buf: bytes, offset: int, question_count: int) -> tuple[list[DNSQuestion], int]:
    questions: list[DNSQuestion] = []

    while len(questions) < question_count:
        labels, offset = read_labels(buf, offset)

        if offset + 4 > len(buf):
            raise ValueError("Truncated question section")
        
        qtype = int.from_bytes(buf[offset:offset + 2], byteorder="big")
        offset += 2
        qclass = int.from_bytes(buf[offset:offset + 2], byteorder="big")
        offset += 2
        
        questions.append(
            DNSQuestion(
                qname=DNSName(labels=labels),
                qtype=qtype,
                qclass=qclass,
            )
        )
    
    return questions, offset

def extract_answers(buf: bytes, offset: int, answer_count: int) -> tuple[list[ResourceRecord], int]:
    answers: list[ResourceRecord] = []
    
    while len(answers) < answer_count:
        labels, offset = read_labels(buf, offset)

        if offset + 10 > len(buf):
            raise ValueError("Truncated answer section")
        
        qtype = int.from_bytes(buf[offset:offset + 2], byteorder="big")
        offset += 2
        qclass = int.from_bytes(buf[offset:offset + 2], byteorder="big")
        offset += 2
        ttl = int.from_bytes(buf[offset:offset + 4], byteorder="big")
        offset += 4
        rdlength = int.from_bytes(buf[offset:offset + 2], byteorder="big")
        offset += 2

        if offset + rdlength > len(buf):
            raise ValueError("Truncated RDATA")

        rdata = buf[offset:offset + rdlength]
        offset += rdlength
        
        answers.append(
            ResourceRecord(
                name=DNSName(labels=labels),
                type=qtype,
                class_=qclass,
                ttl=ttl,
                rdata=rdata,
                rdlength=rdlength
            )
        )
    
    return answers, offset

def parse_request(buf: bytes) -> UDPMessage:
    header = buf[:12]
    headers = extract_headers(header)

    offset = 12
    questions = []
    answers = []

    if headers.qdcount > 0:
        questions, offset = extract_questions(buf, offset, headers.qdcount)
    
    if headers.ancount > 0:
        answers, offset = extract_answers(buf, offset, headers.ancount)

    return UDPMessage(
        headers=headers,
        questions=questions,
        answer=answers
    )

def main(args):
    udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_socket.bind(("127.0.0.1", 2053))
    
    while True:
        try:
            buf, source = udp_socket.recvfrom(512)
            request = parse_request(buf)
            if args.resolver:
                ip, port = args.resolver.split(":")
                response = request.generate_resolver_reponse(ip, int(port))
            else:    
                response = request.generate_response()
    
            udp_socket.sendto(response, source)
        except Exception as e:
            print(f"Error receiving data: {e}")
            break


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="A simple DNS server that listens for UDP requests")
    parser.add_argument("--resolver", type=str)
    args = parser.parse_args()
    main(args)
