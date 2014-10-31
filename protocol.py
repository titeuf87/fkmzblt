import struct
import base64
import uuid
import asyncio
import ssl

CONNECTED = b"\x01"
DISCONNECTED = b"\x02"
PACKET = b"\x03"
DATA = b"\x04"

class NotEnoughDataException(Exception):
    pass

def get_unique_id():
    return base64.b32encode(uuid.uuid4().bytes) \
                 .decode() \
                 .replace("=", "") \
                 .lower()

def encode(connectionid, packettype, data=None):
    msg = connectionid.encode()

    if packettype in (PACKET, DATA):
        msg += packettype + struct.pack("<I", len(data)) + data
    else:
        msg += packettype
    return msg

def decode(data):
    if len(data) < 26 + 1:
        raise NotEnoughDataException()

    connectionid = data[:26]
    packettype = data[26:26+1]
    if packettype in (CONNECTED, DISCONNECTED):
        remaining = data[26+1:]
        return (connectionid.decode(), packettype, None, remaining)
    else:
        if len(data) < 26 + 1 + 4:
            raise NotEnoughDataException()
        packetsize = struct.unpack("<I", data[26+1:26+1+4])[0]
        if len(data) < 26 + 1 + 4 + packetsize:
            raise NotEnoughDataException()

        packet = data[26+1+4:26+1+4+packetsize]
        remaining = data[26+1+4+packetsize:]
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
