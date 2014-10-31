import asyncio
import ssl
import aiohttp
import aiohttp.server

import protocol

downloaders = {}

@asyncio.coroutine
def connect_to_server():
    sslcontext = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
    sslcontext.verify_mode = ssl.CERT_NONE

    sreader, swriter = yield from asyncio.open_connection("share.fkmzblt.net", 443, ssl=sslcontext)

    readbuffer = b""
    data = yield from protocol.read_next_packet(sreader, readbuffer)
    print(data)
    readbuffer = data[3]
    if data[1] == protocol.DATA:
        data = data[2].decode()
        if data.startswith("id"):
            print("https://{}.fkmzblt.net".format(data[2:]))

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
                    remote_writer.write(protocol.encode(connectionid, protocol.PACKET, data))
                else:
                    local_read = None
                    remote_read.cancel()
                    remote_read = None

                    remote_writer.write(protocol.encode(connectionid, protocol.DISCONNECTED))
                    print("all done!")

            elif t == remote_read:
                if data:
                    local_writer.write(data)
                    remote_read = asyncio.async(q.get())
                else:
                    remote_read = None
                    local_writer.close()




@asyncio.coroutine
def run_local_server():
    sslcontext = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
    sslcontext.load_cert_chain(certfile="server.crt", keyfile="server.key")

    #yield from asyncio.start_server(handle_downloader_connected, "127.0.0.1", 6666, ssl=sslcontext)
    loop = asyncio.get_event_loop()
    yield from loop.create_server(HttpRequestHandler, "127.0.0.1", 6666, ssl=sslcontext)

@asyncio.coroutine
def handle_downloader_connected(reader, writer):
    print("meow?")
    try:
        data = yield from reader.read(1024)
    except ssl.SSLError:
        return
    print(data)

class HttpRequestHandler(aiohttp.server.ServerHttpProtocol):

    @asyncio.coroutine
    def handle_request(self, message, payload):
        print(message, payload)

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

        with open("Photo0133.jpg", "rb") as fp:
            chunk = fp.read(8196)
            while chunk:
                response.write(chunk)
                chunk = fp.read(8196)
                yield

        yield from response.write_eof()
        if response.keep_alive():
            print("keepalive")
#            self.keep_alive()

if __name__ == "__main__":
    asyncio.async(connect_to_server())
    asyncio.async(run_local_server())

    loop = asyncio.get_event_loop()
    loop.run_forever()
