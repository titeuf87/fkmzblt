import asyncio
import ssl
import aiohttp
import aiohttp.server
import argparse
import os

import protocol
import proxy

downloaders = {}

@asyncio.coroutine
def connect_to_server():
    sslcontext = ssl.create_default_context()
    sslcontext.load_verify_locations("server.crt")

    create_new_certificate = True

    if os.path.isfile("certificate") and os.path.isfile("privatekey"):
        sslcontext.load_cert_chain(certfile="certificate", keyfile="privatekey")
        create_new_certificate = False

    sreader, swriter = yield from asyncio.open_connection("share.fkmzblt.net", 443, ssl=sslcontext)

    readbuffer = b""
    data = yield from protocol.read_next_packet(sreader, readbuffer)
    print(data)
    readbuffer = data[3]
    if data[1] == protocol.DATA:
        data = data[2].decode()
        if data.startswith("id"):
            host = "{}.fkmzblt.net".format(data[2:])
            fileid = protocol.get_unique_id()
            print("https://{}/{}".format(host, fileid))

            if create_new_certificate:
                print("Making signing request")
                req = create_certificate_signing_request(host)
                swriter.write(protocol.encode(data[2:], protocol.DATA, b"cert" + req))

    if create_new_certificate:
        data = yield from protocol.read_next_packet(sreader, readbuffer)
        if data[1] == protocol.DATA:
            f = open("certificate", "wb")
            cert = data[2][4:]
            f.write(cert)
            cert = open("server.crt", "rb").read()
            f.write(cert)
            f.close()

    asyncio.async(run_local_server(host, args.filename, fileid))

    while True:
        data = yield from protocol.read_next_packet(sreader, readbuffer)
        if not data:
            break
        readbuffer = data[3]

        if data[1] == protocol.CONNECTED:
            print("connected")
            downloaders[data[0]] = asyncio.Queue()
            asyncio.async(handle_connection(data[0], swriter))
        elif data[1] == protocol.PACKET:
            yield from downloaders[data[0]].put(data[2])


@asyncio.coroutine
def handle_connection(connectionid, remote_writer):
    q = downloaders[connectionid]
    print("mew?")
    local_reader, local_writer = yield from asyncio.open_connection("127.0.0.1", 6666)
    print("mew!")

    local_connection = proxy.Connection(
        lambda: local_reader.read(1024),
        lambda data: local_writer.write(data)
    )

    remote_connection = proxy.Connection(
        lambda: q.get(),
        lambda data: remote_writer.write(protocol.encode(connectionid, protocol.PACKET, data))
    )

    p = proxy.Proxy(local_connection, remote_connection)
    yield from p.run()
    remote_writer.write(protocol.encode(connectionid, protocol.DISCONNECTED))

@asyncio.coroutine
def run_local_server(hostname, file_to_share, fileid):
    sslcontext = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
#    cert, pkey = create_tls_certificate(hostname)
    cert = "certificate"
    pkey = "privatekey"
    sslcontext.load_cert_chain(certfile=cert, keyfile=pkey)

    #yield from asyncio.start_server(handle_downloader_connected, "127.0.0.1", 6666, ssl=sslcontext)
    loop = asyncio.get_event_loop()
    yield from loop.create_server(lambda: HttpRequestHandler(file_to_share, fileid), "127.0.0.1", 6666, ssl=sslcontext)

@asyncio.coroutine
def handle_downloader_connected(reader, writer):
    print("meow?")
    try:
        data = yield from reader.read(1024)
    except ssl.SSLError:
        return
    print(data)

class HttpRequestHandler(aiohttp.server.ServerHttpProtocol):

    def __init__(self, file_to_share, fileid, **kwargs):
        super().__init__(**kwargs)
        self.file_to_share = file_to_share
        self.fileid = fileid

    @asyncio.coroutine
    def handle_request(self, message, payload):
        if message.path != "/" + self.fileid:
            response = aiohttp.Response(self.writer, 404, http_version=message.version)
            response.send_headers()
            yield from response.write_eof()
            return

        response = aiohttp.Response(self.writer, 200, http_version=message.version)
        response.add_header('Transfer-Encoding', 'chunked')

        accept_encoding = message.headers.get('accept-encoding', '').lower()
        if 'deflate' in accept_encoding:
            response.add_header('Content-Encoding', 'deflate')
            response.add_compression_filter('deflate')
        elif 'gzip' in accept_encoding:
            response.add_header('Content-Encoding', 'gzip')
            response.add_compression_filter('gzip')
        response.add_chunking_filter(1025)
        response.add_header('Content-type', 'image/png')
        response.send_headers()

        with open(self.file_to_share, "rb") as fp:
            chunk = fp.read(8196)
            while chunk:
                response.write(chunk)
                chunk = fp.read(8196)
                yield

        yield from response.write_eof()
        if response.keep_alive():
            print("keepalive")
#            self.keep_alive()

def create_tls_certificate(common_name):
    import sys
    from random import random
    from OpenSSL import crypto

    pkey = crypto.PKey()
    pkey.generate_key(crypto.TYPE_RSA, 1024)

    cert = crypto.X509()
    cert.set_serial_number(int(random() * sys.maxsize))
    cert.gmtime_adj_notBefore(0)
    cert.gmtime_adj_notAfter(60 * 60 * 24 * 365)

    subject = cert.get_subject()
    subject.CN = common_name
    subject.O = "fkmzblt share"

    issuer = cert.get_issuer()
    issuer.CN = "fkmzblt share"
    issuer.O = "selfsigned"

    cert.set_pubkey(pkey)
    cert.sign(pkey, "sha1")

    import tempfile, os
    cert_handle, cert_file = tempfile.mkstemp()
    pkey_handle, pkey_file = tempfile.mkstemp()

    os.write(cert_handle, crypto.dump_certificate(crypto.FILETYPE_PEM, cert))
    os.write(pkey_handle, crypto.dump_privatekey(crypto.FILETYPE_PEM, pkey))
    os.close(cert_handle)
    os.close(pkey_handle)

    return cert_file, pkey_file

def create_certificate_signing_request(common_name):
    import sys
    from OpenSSL import crypto

    key = crypto.PKey()
    key.generate_key(crypto.TYPE_RSA, 2048)

    req = crypto.X509Req()
    req.get_subject().CN = common_name
    req.set_pubkey(key)
    req.sign(key, "sha1")

    f = open("privatekey", "wb")
    f.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, key))
    f.close()

    f = open("request", "wb")
    f.write(crypto.dump_certificate_request(crypto.FILETYPE_PEM, req))
    f.close()

    return crypto.dump_certificate_request(crypto.FILETYPE_PEM, req)

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("filename", help="path to the file you wish to share")

    args = parser.parse_args()


    asyncio.async(connect_to_server())

    loop = asyncio.get_event_loop()
    loop.run_forever()
