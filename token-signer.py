import sys

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

# Sign token
def get_signature(token):
    digest = SHA256.new(token)
    sign = signer.sign(digest)
    return b64encode(sign)

# HTTP-request handler
class Handler(BaseHTTPRequestHandler):
    # GET-request
    def do_GET(self):
        # Veriffy path
        if self.path.find('/js/token-signer.js?token=') != 0:
            print 'wrong path'
            self.send_response(400)
            return

        # Get referer
        referer = self.headers.getheader('Referer')

        if not referer:
            print 'no referer'
            self.send_response(400)
            return

        # Parse query string to get token
        query = parse_qs(self.path[20:])

        if not 'token' in query:
            print 'no token'
            self.send_response(400)
            return

        token = query['token'][0]

        # Redirect with signed request's token to prove that user reached our server
        sign = get_signature(token)
        self.send_response(302)
        self.send_header('Location', referer + 'js/token-signer.js?token=%s&sign=%s' % (token, sign))
        self.end_headers()

# Start HTTP-server
httpd = HTTPServer(('', port), Handler)
httpd.serve_forever()
