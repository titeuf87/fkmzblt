import asyncio
import ssl
import aiohttp
import aiohttp.server
import argparse
import os
import logging

import sys

import protocol
import proxy

downloaders = {}

@asyncio.coroutine
def connect_to_server():
    sslcontext = ssl.create_default_context()
    sslcontext.load_verify_locations("server.crt")

    create_new_certificate = True

    if os.path.isfile("certificate") and os.path.isfile("privatekey"):
        logging.info("Going to reuse existing certificate.")
        sslcontext.load_cert_chain(certfile="certificate", keyfile="privatekey")
        create_new_certificate = False

    logging.info("Connecting...")
    sreader, swriter = yield from asyncio.open_connection("share.fkmzblt.net", 443, ssl=sslcontext)

    readbuffer = b""
    data = yield from protocol.read_next_packet(sreader, readbuffer)
    readbuffer = data[3]
    if data[1] == protocol.DATA:
        data = data[2].decode()
        if data.startswith("id"):
            host = "{}.fkmzblt.net".format(data[2:])
            fileid = protocol.get_unique_id()
            logging.info("File shared at: https://{}/{}".format(host, fileid))

            if create_new_certificate:
                logging.info("Making a new certificate.")
                req = create_certificate_signing_request(host)
                swriter.write(protocol.encode(data[2:], protocol.DATA, b"cert" + req))

    if create_new_certificate:
        data = yield from protocol.read_next_packet(sreader, readbuffer)
        if data[1] == protocol.DATA:
            logging.info("Server signed our new certificate.")
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
            downloaders[data[0]] = asyncio.Queue()
            asyncio.async(handle_connection(data[0], swriter))
        elif data[1] == protocol.PACKET:
            yield from downloaders[data[0]].put(data[2])


@asyncio.coroutine
def handle_connection(connectionid, remote_writer):
    logging.info("Downloader ({}) connected.".format(connectionid))
    q = downloaders[connectionid]
    local_reader, local_writer = yield from asyncio.open_connection("127.0.0.1", 6666)

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
    logging.info("Downloader ({}) disconnected.".format(connectionid))

@asyncio.coroutine
def run_local_server(hostname, file_to_share, fileid):
    sslcontext = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
    cert = "certificate"
    pkey = "privatekey"
    sslcontext.load_cert_chain(certfile=cert, keyfile=pkey)

    loop = asyncio.get_event_loop()
    yield from loop.create_server(lambda: HttpRequestHandler(file_to_share, fileid), "127.0.0.1", 6666, ssl=sslcontext)

@asyncio.coroutine
def handle_downloader_connected(reader, writer):
    try:
        data = yield from reader.read(1024)
    except ssl.SSLError:
        return

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


def create_certificate_signing_request(common_name):
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
    FORMAT = '%(asctime)s [%(levelname)s] %(message)s'
    logging.basicConfig(format=FORMAT)
    logging.getLogger().setLevel(logging.INFO)

    parser = argparse.ArgumentParser()
    parser.add_argument("filename", help="path to the file you wish to share")

    args = parser.parse_args()


    asyncio.async(connect_to_server())

    loop = asyncio.get_event_loop()
    loop.run_forever()
