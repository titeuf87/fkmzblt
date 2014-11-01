import struct
import base64
import uuid
import asyncio
import ssl
import random
import string

CONNECTED = b"\x01"
DISCONNECTED = b"\x02"
PACKET = b"\x03"
DATA = b"\x04"

ID_LENGTH = 4

class NotEnoughDataException(Exception):
    pass


_symbols = None

def _generate_symbols():
    global _symbols
    _symbols = []
    for x in range(0, ID_LENGTH):
        l = list(string.ascii_lowercase + string.digits)
        random.shuffle(l)
        _symbols.append(l)

def get_unique_id():
    if not _symbols:
        _generate_symbols()

    r = "".join((l.pop() for l in _symbols))
    return r

def encode(connectionid, packettype, data=None):
    msg = connectionid.encode()

    if packettype in (PACKET, DATA):
        msg += packettype + struct.pack("<I", len(data)) + data
    else:
        msg += packettype
    return msg

def decode(data):
    if len(data) < ID_LENGTH + 1:
        raise NotEnoughDataException()

    connectionid = data[:ID_LENGTH]
    packettype = data[ID_LENGTH:ID_LENGTH+1]
    if packettype in (CONNECTED, DISCONNECTED):
        remaining = data[ID_LENGTH+1:]
        return (connectionid.decode(), packettype, None, remaining)
    else:
        if len(data) < ID_LENGTH + 1 + 4:
            raise NotEnoughDataException()
        packetsize = struct.unpack("<I", data[ID_LENGTH+1:ID_LENGTH+1+4])[0]
        if len(data) < ID_LENGTH + 1 + 4 + packetsize:
            raise NotEnoughDataException()

        packet = data[ID_LENGTH+1+4:ID_LENGTH+1+4+packetsize]
        remaining = data[ID_LENGTH+1+4+packetsize:]
        return (connectionid.decode(), packettype, packet, remaining)

@asyncio.coroutine
def read_next_packet(reader, readbuffer):
    try:
        decoded = decode(readbuffer)
        return decoded
    except NotEnoughDataException:
        pass

    while True:
        try:
            data = yield from reader.read(102)
            if not data:
                print("no data")
                return None
        except ssl.SSLError:
            print("ssl error")
            return None

        readbuffer += data
        try:
            decoded = decode(readbuffer)
            return decoded

        except NotEnoughDataException:
            pass

if __name__ == "__main__":
    a = encode(get_unique_id(), CONNECTED) + b"def"
    print(a)
    b = decode(a)
    print(b)
    print()

    a = encode(get_unique_id(), PACKET, b"abc") + b"def"
    print(a)
    b = decode(a)
    print(b)
    print()

    a = encode(get_unique_id(), DATA, b"abc") + b"def"
    print(a)
    b = decode(a)
    print(b)

    a = encode(get_unique_id(), DATA, b"abc")
    print(a)
    print(a[:-1])
    b = decode(a[:-1])
    print(b)
