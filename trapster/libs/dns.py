import struct

# details of dns packet : https://courses.cs.duke.edu/fall16/compsci356/DNS/DNS-primer.pdf
# code from https://stackoverflow.com/questions/16977588/reading-dns-packets-in-python


def decode_labels(message, offset):
    labels = []
    return_offset = None
    # Each pointer must jump strictly backward, so the max legal target
    # shrinks monotonically. This bounds cycles and long chains.
    max_allowed_pointer = len(message)

    while True:
        if offset >= len(message):
            raise ValueError("label offset out of bounds")

        length, = struct.unpack_from("!B", message, offset)

        if (length & 0xC0) == 0xC0:
            pointer, = struct.unpack_from("!H", message, offset)
            # Remember where to resume only for the first pointer followed.
            if return_offset is None:
                return_offset = offset + 2
            target = pointer & 0x3FFF
            if target >= max_allowed_pointer:
                raise ValueError("invalid DNS compression pointer")
            max_allowed_pointer = target
            offset = target
            continue

        if (length & 0xC0) != 0x00:
            raise ValueError("unknown label encoding")

        offset += 1

        if length == 0:
            return labels, return_offset if return_offset is not None else offset

        labels.append(*struct.unpack_from(f"!{length}s", message, offset))
        try:
            labels[-1] = labels[-1].decode()
        except UnicodeDecodeError:
            labels[-1] = str(labels[-1])

        offset += length


DNS_QUERY_SECTION_FORMAT = struct.Struct("!2H")

def decode_question_section(message, offset, qdcount):
    questions = []

    for _ in range(qdcount):
        qname, offset = decode_labels(message, offset)

        qtype, qclass = DNS_QUERY_SECTION_FORMAT.unpack_from(message, offset)
        offset += DNS_QUERY_SECTION_FORMAT.size

        question = {"domain_name": qname,
                    "query_type": qtype,
                    "query_class": qclass}

        questions.append(question)

    return questions, offset


DNS_QUERY_MESSAGE_HEADER = struct.Struct("!6H")

def decode_dns_message(message):
    try:
        id, flags, qdcount, ancount, nscount, arcount = DNS_QUERY_MESSAGE_HEADER.unpack_from(message)
        
        qr = (flags & 0x8000) != 0 
        opcode = (flags & 0x7800) >> 11 
        aa = (flags & 0x0400) != 0 
        tc = (flags & 0x200) != 0 
        rd = (flags & 0x100) != 0 
        ra = (flags & 0x80) != 0
        z = (flags & 0x70) >> 4
        rcode = flags & 0xF

        offset = DNS_QUERY_MESSAGE_HEADER.size
        questions, offset = decode_question_section(message, offset, qdcount)

        result = {"id": id,
                "is_response": qr,
                "opcode": opcode,
                "is_authoritative": aa,
                "is_truncated": tc,
                "recursion_desired": rd,
                "recursion_available": ra,
                "reserved": z,
                "response_code": rcode,
                "question_count": qdcount,
                "answer_count": ancount,
                "authority_count": nscount,
                "additional_count": arcount,
                "questions": questions}

        return result
    except struct.error as e:
        raise ValueError(f"truncated DNS message: {e}") from e

