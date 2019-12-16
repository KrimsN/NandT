import socket
import select
from socketserver import ThreadingMixIn, TCPServer, StreamRequestHandler
import struct

DEBUG = False

class ThreadingTCPServer(ThreadingMixIn, TCPServer):
    pass


class SocksProxy(StreamRequestHandler):
    SOCKS_VERSION = 5

    def handle(self):
        print(f'Client from {self.client_address}')
        header = self.connection.recv(2)
        version, nmethods = struct.unpack("!BB", header)

        if DEBUG: print(f'header={header}')
        assert version == SocksProxy.SOCKS_VERSION
        assert nmethods > 0

        methods = self.get_methods(nmethods)
        if DEBUG: print(f'methods={methods}')

        # 0 - noauth
        if 0 not in methods:
            self.connection.sendall(struct.pack("!BB",
                                                self.SOCKS_VERSION, 0xFF))
            self.server.close_request(self.request)
            return
        self.connection.sendall(struct.pack("!BB",
                                            self.SOCKS_VERSION, 0))

        replycode, cmd, remote = self.get_reqdetails()
        if DEBUG: print(f'reply={replycode} cmd={cmd}')
        if replycode == 0 and cmd == 1:
            self.proxy_loop(self.connection, remote)
        self.server.close_request(self.request)

    def get_methods(self, n):
        # получить n методов от клиента
        return [ord(self.connection.recv(1)) for i in range(n)]

    def get_reqdetails(self):
        version, cmd, _, atype = struct.unpack("!BBBB",
                                               self.connection.recv(4))
        if DEBUG: print(version, cmd, atype)

        assert version == self.SOCKS_VERSION

        if atype == 1:  # IPV4
            address = socket.inet_ntoa(self.connection.recv(4))
        elif atype == 3:  # DNS
            dom_len = ord(self.connection.recv(1))
            address = self.connection.recv(dom_len)

        port = struct.unpack("!H", self.rfile.read(2))[0]

        try:
            if cmd == 1:  # CONNECT
                remote = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                remote.connect((address, port))
                bind_address = remote.getsockname()
                print(f'Connected to {(address, port)}')
            else:
                self.server.close_request(self.request)

            addr = struct.unpack("!I", socket.inet_aton(bind_address[0]))[0]
            port = bind_address[1]
            # 0x00 Connection granted
            rcode = 0
            reply = struct.pack("!BBBBIH",
                                self.SOCKS_VERSION,
                                rcode,
                                0,
                                atype,
                                addr,
                                port)
        except Exception:
            # 0x05 Connection refused
            rcode = 5
            reply = self.generate_failed_reply(atype, rcode)
        self.connection.sendall(reply)
        return rcode, cmd, remote

    def generate_failed_reply(self, atype, code):
        return struct.pack("!BBBBIH",
                           self.SOCKS_VERSION,
                           code,
                           0,
                           atype,
                           0,
                           0)

    def proxy_loop(self, client, remote):
        while True:
            r, w, e = select.select([client, remote], [], [])

            if client in r:
                data = client.recv(4096)
                if remote.send(data) < 0:
                    break


            if remote in r:
                data = remote.recv(4096)
                if client.send(data) < 0:
                    break



import argparse

def main():
    p = argparse.ArgumentParser()
    p.add_argument('host')
    p.add_argument('port', type=int)

    args = p.parse_args()
    addr = (args.host, args.port)

    with ThreadingTCPServer(addr, SocksProxy) as s:
        s.serve_forever()


if __name__ == '__main__':
    main()
