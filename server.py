import asyncio
import ssl

import tls
import ssl
import protocol


def start_proxy_server():
    coro = asyncio.start_server(proxy_client_connected, '0.0.0.0', 443)
    asyncio.async(coro)

def start_sharer_server():
    sslcontext = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
    sslcontext.load_cert_chain(certfile="server.crt", keyfile="server.key")
    sslcontext.verify_mode = ssl.CERT_NONE
    coro = asyncio.start_server(sharer_client_connected, '127.0.0.1', 4446,
        ssl=sslcontext)
    asyncio.async(coro)

@asyncio.coroutine
def proxy_client_connected(reader, writer):
    print("Client connected")
    while True:
        data = yield from reader.read(1024)
        hostname = tls.get_sni(data)

        if not hostname or "." not in hostname:
            writer.close()
            return

        subdomain = hostname[:hostname.find(".")]
        if subdomain == "share":
            yield from sharer_connected_to_proxy(data, reader, writer)
        elif subdomain in sharers:
            yield from downloader_connected_to_proxy(data, subdomain, reader, writer)

@asyncio.coroutine
def sharer_connected_to_proxy(original_data, local_reader, local_writer):
    remote_reader, remote_writer = \
        yield from asyncio.open_connection("127.0.0.1", 4446)

    remote_writer.write(original_data)

    local_read = asyncio.async(local_reader.read(1024))
    remote_read = asyncio.async(remote_reader.read(1024))

    while local_read or remote_read:
        waits = [t for t in (local_read, remote_read) if t]
        done, pending = yield from asyncio.wait(waits,
            return_when=asyncio.FIRST_COMPLETED)

        for t in done:
            data = t.result()

            if t == local_read:
                if data:
                    local_read = asyncio.async(local_reader.read(1024))
                    remote_writer.write(data)
                else:
                    local_read = None
                    remote_writer.close()

            elif t == remote_read:
                if data:
                    remote_read = asyncio.async(remote_reader.read(1024))
                    local_writer.write(data)
                else:
                    remote_read = None
                    local_writer.close()

@asyncio.coroutine
def downloader_connected_to_proxy(original_data, sharerid, local_reader, local_writer):
    downloaderid = protocol.get_unique_id()
    downloaders[downloaderid] = asyncio.Queue()
    q = downloaders[downloaderid]

    remote_writer = sharers[sharerid]
    remote_writer.write(protocol.encode(downloaderid, protocol.CONNECTED))
    remote_writer.write(protocol.encode(downloaderid, protocol.PACKET, original_data))

    local_read = asyncio.async(local_reader.read(1024))
    remote_read = asyncio.async(q.get())

    while local_read or remote_read:
        waits = [t for t in (local_read, remote_read) if t]
        done, pending = yield from asyncio.wait(waits,
            return_when=asyncio.FIRST_COMPLETED)

        for t in done:
            data = t.result()

            if t == local_read:
                if data:
                    local_read = asyncio.async(local_reader.read(1024))
                    remote_writer.write(protocol.encode(downloaderid, protocol.PACKET, data))
                else:
                    local_read = None
                    #remote_writer.close()

            elif t == remote_read:
                if data:
                    remote_read = asyncio.async(q.get())
                    local_writer.write(data)
                else:
                    remote_read = None
                    local_writer.close()

    del downloaders[downloaderid]
#    while True:
#        data = yield from local_reader.read(1024)

sharers = {}
downloaders = {}

@asyncio.coroutine
def sharer_client_connected(reader, writer):
    sharerid = protocol.get_unique_id()
    print("Sharerid: {}".format(sharerid))
    sharers[sharerid] = writer
    writer.write(protocol.encode(sharerid, protocol.DATA, b"id" + sharerid.encode()))

    try:
        readbuffer = b""
        while True:
            packet = yield from protocol.read_next_packet(reader, readbuffer)
            if not packet:
                return
            readbuffer = packet[3]
            connectionid = packet[0]

            if packet[1] == protocol.PACKET:
                yield from downloaders[connectionid].put(packet[2])
            elif packet[1] == protocol.DISCONNECTED:
                print("downloader disconnected")
                yield from downloaders[connectionid].put(None)
    finally:
        del sharers[sharerid]


if __name__ == "__main__":
    loop = asyncio.get_event_loop()
    start_proxy_server()
    start_sharer_server()

    loop.run_forever()
