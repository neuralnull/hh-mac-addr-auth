import sys
import select
import time

from BaseHTTPServer import BaseHTTPRequestHandler, HTTPServer
from urlparse import parse_qs

from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5
from Crypto.Hash import SHA256 
from base64 import b64encode, b64decode

# Get port number from 1st argument ...
port = int(sys.argv[1])
# ... and private key filename from 2nd
key_location = sys.argv[2]

# Create signer
rsakey = RSA.importKey(open(key_location, "r").read())
signer = PKCS1_v1_5.new(rsakey)

# Sign token and MAC-address
def get_signature(token, mac):
    digest = SHA256.new(token + mac)
    sign = signer.sign(digest)
    return b64encode(sign)

# We assume to get MAC-address for each request with unique token from stdin (piped tcpdump)
# Data contains key value pairs "token -> (MAC-address, getting time)"
stdin_data = {}
# We hold unused data no longer than this number of seconds
stdin_data_ttl = 60.0

# Try to read token and MAC-address from stdin
def read_stdin_data():
    # Check if we have data on stdin with 5 sec timeout
    has_data =  select.select([sys.stdin], [], [], 5.0)[0]
    while has_data:
        # Get next line from stdin and split it into token and MAC-address
        data = sys.stdin.readline().split(' ', 1)
        if len(data) > 1:
            stdin_data[data[0].strip()] = {
                'mac': data[1].strip(),
                # Data reading time
                'time': time.time()
            }
        # Check if we have more data (without waiting)
        has_data = select.select([sys.stdin], [], [], 0.0)[0]

# Try to take MAC-address from read data
def get_mac_by_token(token):
    current_time = time.time()
    # First we remove old data
    for token, data in stdin_data.items():
        if current_time - data['time'] > stdin_data_ttl:
            del stdin_data[token]
    # Then we try to get requested data and remove it from dict
    if token in stdin_data:
        return stdin_data.pop(token)['mac']

# HTTP-request handler
class Handler(BaseHTTPRequestHandler):
    # GET-request
    def do_GET(self):
        # Veriffy path
        if self.path.find('/mac-addr-auth.js?token=') != 0:
            self.send_response(400)
            return

        # Parse query string to get token
        query = parse_qs(self.path[18:])

        if not 'token' in query:
            self.send_response(400)
            return

        token = query['token'][0]

        # Try to read info about request from piped tcpdump
        read_stdin_data()
        mac = get_mac_by_token(token)

        # If no info found for our request, we return failure response
        if not mac:
            self.send_response(400)
            return

        # Otherwise we return signed request's token and MAC as javascript
        # to prove that user reached our server
        sign = get_signature(token, mac)
        self.send_response(200)
        self.send_header('Content-type', 'application/javascript')
        self.end_headers()
        self.wfile.write("proveMacAddrAuth({'token':'%s','mac':'%s','sign':'%s'});" % (token, mac, sign))

# Start HTTP-server
httpd = HTTPServer(('', port), Handler)
httpd.serve_forever()
