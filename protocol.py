import struct
import base64
import uuid
import asyncio
import ssl

CONNECTED = 0xffffffff
DISCONNECTED = 0xfffffffe
PACKET = 0x00000000

class NotEnoughDataException(Exception):
    pass

def get_unique_id():
    return base64.b32encode(uuid.uuid4().bytes) \
                 .decode() \
                 .replace("=", "") \
                 .lower()

def encode(connectionid, packettype, data=None):
    msg = connectionid.encode()

    if packettype == PACKET:
        msg += struct.pack("<I", len(data)) + data
    else:
        msg += struct.pack("<I", packettype)

    return msg

def decode(data):
    if len(data) < 26 + 4:
        raise NotEnoughDataException()

    connectionid = data[:26].decode()
    packettype = struct.unpack("<I", data[26:26+4])[0]
    if packettype in (CONNECTED, DISCONNECTED):
        remaining = data[26+4:]
        return (connectionid, packettype, None, remaining)
    else:
        if len(data) < 26 + 4 + packettype:
            raise NotEnoughDataException()

        packet = data[26+4:26+4+packettype]
        remaining = data[26+4+packettype:]
        return (connectionid, PACKET, packet, remaining)

@asyncio.coroutine
def read_next_packet(reader, readbuffer):
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
    b = decode(a)
    print(b)

    a = encode(get_unique_id(), PACKET, b"abc") + b"def"
    b = decode(a)
    print(b)
