# openssl req -new -x509 -keyout server.pem -out server.pem -days 365 -nodes

import http.server
import ssl

httpd = http.server.HTTPServer(
    ('localhost', 4443), http.server.SimpleHTTPRequestHandler)
httpd.socket = ssl.wrap_socket(
    httpd.socket, certfile='./server.pem', server_side=False)
httpd.serve_forever()
