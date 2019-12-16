import http.server as s
import http.client as c
from socketserver import ThreadingMixIn
import argparse


import urllib.parse as urlparse
from copy import deepcopy
import os
import pathlib
import hashlib
import pickle


class ProxyHandler(s.BaseHTTPRequestHandler):
    class SerializedResponse:
        def __init__(self, headers, body):
            self.headers = headers
            self.body = body

        def serialize(self, fname):
            pickle.dump(self, open(fname, 'wb'),
                        protocol=pickle.HIGHEST_PROTOCOL)

        @classmethod
        def deserialize(cls, fname):
            return pickle.load(open(fname, 'rb'))

    CACHE_DIR = 'cache'
    if not os.path.exists(CACHE_DIR):
        os.mkdir(CACHE_DIR)

    def prepare_request(self):
        requested_url = self.requestline.split()[1]
        parsed_url = urlparse.urlsplit(requested_url)
        cut_url = urlparse.urlunsplit(('', '', parsed_url.path, parsed_url.query, ''))

        req_headers = deepcopy(self.headers)

        ret = {'host': parsed_url.hostname,
               'port': parsed_url.port,
               'uri': requested_url,
               'headers': req_headers}

        return ret

    def make_filename(self, uri: str):
        h = hashlib.md5()
        h.update(uri.encode())
        digest = h.hexdigest()
        path = pathlib.Path(ProxyHandler.CACHE_DIR)
        path = path / (digest + '.cached')
        return str(path)

    def load_response(self, fname) -> c.HTTPResponse:
        return pickle.load(open(fname, 'rb'))

    def send_req(self, prep, method, body=None):
        conn = c.HTTPConnection(prep['host'], prep['port'])
        print(prep, body)
        conn.request(method, prep['uri'], body=body, headers=prep['headers'])
        resp = conn.getresponse()
        return resp, conn

    def send_headers(self, resp):
        for key in resp.headers:
            self.send_header(key, resp.headers[key])
        self.end_headers()

    def do_GET(self):
        print('--------get----------')
        print(self.requestline)
        prep = self.prepare_request()
        uri = self.requestline.split()[1]
        print(uri)
        fname = self.make_filename(uri)
        files = os.listdir(ProxyHandler.CACHE_DIR)

        date = None
        etag = None
        # есть файл в кеше
        try:
            if fname.split('\\')[1] in files:
                print('cache hit, deserealizing')
                cresp = self.SerializedResponse.deserialize(fname)
                date = cresp.headers['Last-Modified']
                etag = cresp.headers['ETag']
                redl = False
            else:
                redl = True
        except:
            print('Err')
            redl = True

        print(date)
        prep['headers'].add_header('Cache-Control', 'max-age=86400')
        # загружена дата модификации
        if date is not None:
            prep['headers'].add_header('If-Modified-Since', date)
        if etag is not None:
            prep['headers'].add_header('If-None-Match', etag)

        resp, conn = self.send_req(prep, 'GET')
        print(f'etag={resp.headers["ETag"]}')
        print(resp.status)
        print(f"lastmod={resp.headers['Last-Modified']}")
        # 304 Not Modified

        if resp.status == 304 and not redl:
            print(f'{uri} was not modified, sending copy')
            self.send_response(200)
            self.send_headers(cresp)
            self.wfile.write(cresp.body)
        else:
            print(f'{uri} was modified, requesting')
            headers = resp.headers
            body = resp.read()
            self.send_response(resp.status)
            for key in headers:
                self.send_header(key, headers[key])
            self.end_headers()
            self.wfile.write(body)
            if resp.status == 200:
                newresp = self.SerializedResponse(headers, body)
                newresp.serialize(fname)

        conn.close()
        self.connection.close()

        print('------end get---------')
        return 0

    def do_POST(self):
        print('--------post----------')
        prep = self.prepare_request()

        body = self.rfile.read(int(self.headers['content-length']))
        
        resp, conn = self.send_req(prep, 'POST', body)
        print(resp.status)
        self.send_response(resp.status)

        self.send_headers(resp)

        html = resp.read()
        self.wfile.write(html)

        conn.close()
        self.connection.close()
        print('------end post---------')
        return 0

    def log_message(self, format, *args):
        return


class ThreadedHTTPServer(ThreadingMixIn, s.HTTPServer):
    daemon_threads = True


def main():
    p = argparse.ArgumentParser()
    p.add_argument('host')
    p.add_argument('port', type=int)

    args = p.parse_args()
    addr = (args.host, args.port)

    httpd = ThreadedHTTPServer(addr, ProxyHandler)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
