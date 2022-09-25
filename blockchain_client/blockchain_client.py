from flask import Flask, request, jsonify, render_template
import Crypto
import Crypto.Random
from Crypto.PublicKey import RSA
import binascii
from collections import OrderedDict
from Crypto.Signature import PKCS1_v1_5
from Crypto.Hash import SHA
from Crypto import Random
from Crypto.Cipher import AES
import base64
import hashlib
import pyodbc


class AESCipher(object):

    def __init__(self, key):
        self.bs = AES.block_size
        self.key = hashlib.sha256(key.encode()).digest()

    def encrypt(self, raw):
        raw = self._pad(raw)
        iv = Random.new().read(AES.block_size)
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return base64.b64encode(iv + cipher.encrypt(raw.encode()))

    def decrypt(self, enc):
        enc = base64.b64decode(enc)
        iv = enc[:AES.block_size]
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return self._unpad(cipher.decrypt(enc[AES.block_size:])).decode('utf-8', "ignore")

    def _pad(self, s):
        return s + (self.bs - len(s) % self.bs) * chr(self.bs - len(s) % self.bs)

    @staticmethod
    def _unpad(s):
        return s[:-ord(s[len(s)-1:])]


""" will be generate sk use RSA (Asymmetric) , this sk will use in all enc/dec operation """
"""random_gen = Crypto.Random.new().read
private_key_enc = RSA.generate(2048, random_gen)
private_key_enc = binascii.hexlify(private_key_enc.export_key(format('DER'))).decode('ascii'),"""

""" will be enc/dec use AES(Symmetric) , this aes obj will use to all enc/dec operations"""

aes = AESCipher(str("private_key_enc"))


class Transaction:

    def __init__(self, sender_public_key, sender_private_key, recipient_public_key, amount):
        self.sender_public_key = sender_public_key
        self.sender_private_key = sender_private_key
        self.recipient_public_key = recipient_public_key
        self.amount = amount

    def to_dict(self):
        return OrderedDict({
            'sender_public_key': self.sender_public_key,
            'recipient_public_key': self.recipient_public_key,
            'amount': self.amount,
        })
    def sign_transaction(self):
        private_key = RSA.import_key(binascii.unhexlify(self.sender_private_key))
        signer = PKCS1_v1_5.new(private_key) #here used to generate signeture
        hash = SHA.new(str(self.to_dict()).encode('utf8')) #this is hash to transaction details
        #then use signer , we will signing to the hash
        #use signer and hash , we will work digital signiture
        return binascii.hexlify(signer.sign(hash)).decode('ascii') # this is digital signiture


app = Flask(__name__)


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/generate/transaction', methods=['POST'])
def generate_transaction():

    # smart contract
    sender_public_key = request.form['sender_public_key']
    sender_private_key = request.form['sender_private_key']
    recipient_public_key = request.form['recipient_public_key']
    amount = request.form['amount']

    transaction = Transaction(sender_public_key, sender_private_key, recipient_public_key, amount)

    response = {'transaction': transaction.to_dict(),
                'signature': transaction.sign_transaction()}

    return jsonify(response), 200


@app.route('/make/transaction')
def make_transaction():
    return render_template('make_transaction.html')


@app.route('/view/transactions')
def view_transactions():
    return render_template('view_transactions.html')


@app.route('/wallet/new')
def new_wallet():
    random_gen = Crypto.Random.new().read
    private_key = RSA.generate(2048, random_gen)
    public_key = private_key.publickey()
    response = {
        'private_key': binascii.hexlify(private_key.export_key(format('DER'))).decode('ascii'),
        'public_key': binascii.hexlify(public_key.export_key(format('DER'))).decode('ascii')
    }
    print(len(aes.encrypt(response['private_key']).decode("utf-8")))
    # print(len(response['public_key']))


    return jsonify(response), 200


if __name__ == '__main__':
    from argparse import ArgumentParser

    parser = ArgumentParser()
    parser.add_argument('-p', '--port', default=8081, type=int, help="port to listen to")
    args = parser.parse_args()
    port = args.port

    app.run(host='127.0.0.1', port=port, debug=True)
