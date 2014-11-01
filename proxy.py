import asyncio
import collections

Connection = collections.namedtuple("Connection", ["read_fn", "write_fn"])

class Connection():
    """
    A connection that can be used for proxying. Every connection contains two
    methods: a read function and a write function.

    The read function should be a coroutine and takes no parameters. This
    gets called to read data from this connection. Should return None or ""
    when the connection is closed.

    The write function should take one parameter and gets called whenever data
    should be written to this connection.
    """

    def __init__(self, read_fn, write_fn):
        """
        Constructor.
        read_fn: a coroutine function that takes no parameter
        write_fn: a function that takes one parameter
        """
        self.read_fn = read_fn
        self.write_fn = write_fn

class Proxy():
    """
    A proxy between two connections: A and B. Everything read from one
    connection gets sent to the other one, and the other way around.
    """

    def __init__(self, connection_a, connection_b):
        """
        Constructor.
        connection_a and connection_b should both be Connection instances.
        """
        self.connection_a = connection_a
        self.connection_b = connection_b

    @asyncio.coroutine
    def run(self):
        """
        Runs the proxy, returning whenever one side closed the connection.
        """

        read_a = asyncio.async(self.connection_a.read_fn())
        read_b = asyncio.async(self.connection_b.read_fn())

        while read_a or read_b:
            waits = [t for t in (read_a, read_b) if t]
            done, pending = yield from asyncio.wait(waits,
                return_when=asyncio.FIRST_COMPLETED)

            for task in done:
                data = task.result()

                if task == read_a:
                    if data:
                        read_a = asyncio.async(self.connection_a.read_fn())
                        self.connection_b.write_fn(data)
                    else:
                        read_a = None
                        read_b.cancel()
                        read_b = None
                elif task == read_b:
                    if data:
                        read_b = asyncio.async(self.connection_b.read_fn())
                        self.connection_a.write_fn(data)
                    else:
                        read_b = None
                        read_a.cancel()
                        read_a = None

