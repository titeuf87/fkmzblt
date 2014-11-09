import asyncio
import ssl
import random
import sys
from OpenSSL import crypto

import tls
import ssl
import protocol
import proxy

def start_proxy_server():
    coro = asyncio.start_server(proxy_client_connected, '0.0.0.0', 443)
    asyncio.async(coro)

def start_sharer_server():
    sslcontext = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
    sslcontext.load_cert_chain(certfile="server.crt", keyfile="server.key")
    sslcontext.load_verify_locations("server.crt")
    sslcontext.verify_mode = ssl.CERT_OPTIONAL
    coro = asyncio.start_server(sharer_client_connected, '127.0.0.1', 4446,
        ssl=sslcontext)
    asyncio.async(coro)

@asyncio.coroutine
def proxy_client_connected(reader, writer):
    print("Client connected")

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

    local_connection = proxy.Connection(
        lambda: local_reader.read(1024),
        lambda data: local_writer.write(data)
    )

    remote_connection = proxy.Connection(
        lambda: remote_reader.read(1024),
        lambda data: remote_writer.write(data)
    )

    p = proxy.Proxy(local_connection, remote_connection)
    yield from p.run()
    remote_writer.close()
    local_writer.close()

@asyncio.coroutine
def downloader_connected_to_proxy(original_data, sharerid, local_reader, local_writer):
    downloaderid = protocol.get_unique_id()
    downloaders[downloaderid] = asyncio.Queue()
    q = downloaders[downloaderid]

    remote_writer = sharers[sharerid]
    remote_writer.write(protocol.encode(downloaderid, protocol.CONNECTED))
    remote_writer.write(protocol.encode(downloaderid, protocol.PACKET, original_data))

    local_connection = proxy.Connection(
        lambda: local_reader.read(1024),
        lambda data: local_writer.write(data)
    )

    remote_connection = proxy.Connection(
        lambda: q.get(),
        lambda data: remote_writer.write(protocol.encode(downloaderid, protocol.PACKET, data))
    )

    p = proxy.Proxy(local_connection, remote_connection)
    yield from p.run()
    local_writer.close()
    print("all done")

    del downloaders[downloaderid]

sharers = {}
downloaders = {}

@asyncio.coroutine
def sharer_client_connected(reader, writer):
    cert = writer.get_extra_info("socket").getpeercert()
    if cert:
        print(cert)
        for sub in cert.get("subject", ()):
            for key, value in sub:
                if key == "commonName":
                    sharerid = value.replace(".fkmzblt.net", "")
    else:
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
            elif packet[1] == protocol.DATA:
                print("data")
                yield from sharer_handle_data(sharerid, reader, writer, packet[2])
    finally:
        del sharers[sharerid]

@asyncio.coroutine
def sharer_handle_data(sharerid, reader, writer, data):
    if data.startswith(b"cert"):
        certificate = data[4:]

        ca_cert = crypto.load_certificate(crypto.FILETYPE_PEM, open("server.crt", "rb").read())
        ca_key = crypto.load_privatekey(crypto.FILETYPE_PEM, open("server.key", "rb").read())

        req = crypto.load_certificate_request(crypto.FILETYPE_PEM, certificate)

        cert = crypto.X509()
        cert.set_subject(req.get_subject())
        cert.set_serial_number(int(random.random() * sys.maxsize))
        cert.gmtime_adj_notBefore(0)
        cert.gmtime_adj_notAfter(24*60*60)
        cert.set_issuer(ca_cert.get_subject())
        cert.set_pubkey(req.get_pubkey())
        cert.sign(ca_key, "sha1")

        signed_cert = crypto.dump_certificate(crypto.FILETYPE_PEM, cert)
        writer.write(protocol.encode(sharerid, protocol.DATA, b"cert" + signed_cert))

if __name__ == "__main__":
    loop = asyncio.get_event_loop()
    start_proxy_server()
    start_sharer_server()

    loop.run_forever()
