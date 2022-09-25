import binascii
from Crypto.PublicKey import RSA

from flask import Flask,jsonify,request, render_template
from time import time
from flask_cors import CORS
from collections import OrderedDict
from Crypto.Signature import PKCS1_v1_5
from Crypto.Hash import SHA
from uuid import uuid4

# this is constant var , this is miner
MINING_SENDER = 'The Block Chain'
MINING_REWORD = 1


class Blockchain:

    def __init__(self):
        self.transactions = []
        self.chain = []
        # generate unique random id
        self.node_id = str(uuid4()).replace('-', '')
        # Create the genesis block
        self.create_block(0, '00')

    def create_block(self, nonce, previous_hash):
        """
        Add a block of transactions to the blockchain
        """
        block = {'block_number': len(self.chain) + 1,
                 'timestamp': time(),
                 'transactions': self.transactions,
                 'nonce': nonce,
                 'previous_hash': previous_hash}

        # Reset the current list of transactions
        self.transactions = []
        self.chain.append(block)
        return block

    def verify_transaction_signature(self,sender_public_key,signature,transaction):
        #استخراج ال ببلك كي الاصلي
        public_key=RSA.importKey(binascii.unhexlify(sender_public_key))
        verifier=PKCS1_v1_5.new(public_key)
        hash=SHA.new(str(transaction).encode('utf8'))#hash to transaction
        try:
            verifier.verify(hash,binascii.unhexlify(signature))#this method return true or false
            return True
        except ValueError:
            return False

    def submit_transaction(self,sender_pk,recipient_pk,signature,amount):
        # TODO : reword the miner

        transaction = OrderedDict({
            'sender_public_key':sender_pk,
            'recipient_public_key':recipient_pk,
            'amount':amount
        })
        if sender_pk == MINING_SENDER :
            # without the verification , transaction from miner to wallet
            self.transactions.append(transaction)
            return len(self.chain) + 1
        else:
            # transaction from wallet to another wallet
            # signature validation , if signature valid ,the we want to add the transaction in the list of transaction .
            # else : then not add this transaction and return false
            signature_verification = self.verify_transaction_signature(sender_pk,signature,transaction)
            if signature_verification:
                self.transactions.append(transaction)
                # here will be added data in database, this done throw return response consist value = true, then will be done ajax requast to added data in database
                return len(self.chain)+1  # this is number of block , that trannsaction added in
            else:
                return False

    # this method to calculate nonce
    def proof_of_work(self):
        return 1234;

    def hash(self,last_block):
        return 'abc'

# Instantiate the Blockchain
blockchain = Blockchain()

# Instantiate the Node
app = Flask(__name__)
CORS(app)

@app.route('/')
def index():
    return render_template('./index.html')


@app.route('/chain', methods=['GET'])
def get_chain():
    response = {
        'chain': blockchain.chain,
        'length': len(blockchain.chain)
    }
    return jsonify(response),200


@app.route('/mine', methods=['GET'])
def mine():
    # Mining steps:
    # we run the proof of work algorithm
    # 1. find nonce , depend on proof of work
    nonce = blockchain.proof_of_work()
    # 2. reword miner
    # now , will create new transaction(called reword) , from blockchain(sender) to miner(recipient)
    blockchain.submit_transaction(MINING_SENDER,
                                  blockchain.node_id,
                                  '',
                                  MINING_REWORD)
    # 3. create new block , and added in this block all transactions
    """ 
    find previous hash
    """
    last_block = blockchain.chain[-1]
    """
    hash() method , create hash to last block
    """
    prev_hash = blockchain.hash(last_block)
    block = blockchain.create_block(nonce, prev_hash)

    response = {
        'message': 'New block created',
        'block_number': block['block_number'],
        'transactions': block['transactions'],
        'nonce': block['nonce'],
        'previous_hash': block['previous_hash']
    }
    return jsonify(response), 200


@app.route('/transactions/new', methods=['POST'])
def new_transaction():
    values=request.form
    transaction_result=blockchain.submit_transaction(values['confirmation_sender_public_key'],
                                                     values['confirmation_recipient_public_key'],
                                                     values['transaction_signature'],
                                                     values['confirmation_amount'])
    if(transaction_result==False):
        response = {'message': 'Invalid'}
        return jsonify(response),406
    else:
        print(transaction_result)
        response = {'message': 'valid and added transaction in the block number = '+str(transaction_result)}
        return jsonify(response), 201  #because we need create new resource(new transaction)


@app.route('/transactions/get',methods=['GET'])
def get_transactions():
    transactions = blockchain.transactions
    response = {'transactions': transactions}
    return jsonify(response), 200

if __name__ == '__main__':
    from argparse import ArgumentParser

    parser = ArgumentParser()
    parser.add_argument('-p', '--port', default=5001, type=int, help="port to listen to")
    args = parser.parse_args()
    port = args.port

    app.run(host='127.0.0.1', port=port, debug=True)
