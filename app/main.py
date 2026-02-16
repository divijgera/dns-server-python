import socket
from dataclasses import dataclass

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
    
    def generate_response(self) -> bytes:
        response_headers = DNSHeader(
            id=1234,
            qr=1,
            opcode=0,
            aa=0,
            tc=0,
            rd=0,
            ra=0,
            z=0,
            rcode=0,
            qdcount=self.headers.qdcount,
            ancount=len(self.answer) if self.answer else 0,
            nscount=0,
            arcount=0,
        )
        
        return self.to_bytes(response_headers, self.questions, self.answer)

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

def extract_question(buf: bytes, question_count: int) -> DNSQuestion:
    questions: list[DNSQuestion] = []
    offset = 0

    while len(questions) < question_count:
        labels = []
        while True:
            length = buf[offset]
            if length == 0:
                offset += 1
                break
            offset += 1
            labels.append(buf[offset:offset + length].decode("utf-8"))
            offset += length

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
    
    return questions

def generate_answer(questions: list[DNSQuestion]) -> list[ResourceRecord]:
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

def parse_request(buf: bytes) -> UDPMessage:
    header = buf[:12]
    headers = extract_headers(header)

    remaining_buf = buf[12:]
    questions = None
    answer = None

    if headers.qdcount > 0:
        questions = extract_question(remaining_buf, headers.qdcount)
        answer = generate_answer(questions)

    return UDPMessage(
        headers=headers,
        questions=questions if questions else [],
        answer=answer if answer else []
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
