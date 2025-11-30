from flask import Flask, request, jsonify, render_template
from time import time
from flask_cors import CORS
from collections import OrderedDict
import binascii
import Crypto
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5
from Crypto.Hash import SHA
from uuid import uuid4
import json
import hashlib
import requests
from urllib.parse import urlparse


MINING_SENDER = "The Blockchain"
MINING_REWARD = 1
MINING_DIFFICULTY = 2


class Blockchain:

    def __init__(self):
        self.transactions = []
        self.chain = []
        self.nodes = set()
        self.node_id = str(uuid4()).replace('-', '')
        # Create the genesis block
        self.create_block(0, '00')

    def register_node(self, node_url):
        parsed_url = urlparse(node_url)
        if parsed_url.netloc:
            self.nodes.add(parsed_url.netloc)
        elif parsed_url.path:
            self.nodes.add(parsed_url.path)
        else:
            raise ValueError('Invalid URL')

    def create_block(self, nonce, previous_hash):
        block = {'block_number': len(self.chain) + 1,
                 'timestamp': time(),
                 'transactions': self.transactions,
                 'nonce': nonce,
                 'previous_hash': previous_hash}
        self.transactions = []
        self.chain.append(block)
        return block

    def verify_transaction_signature(self, librarian_public_key, signature, transaction):
        try:
            
            public_key = RSA.importKey(binascii.unhexlify(librarian_public_key))
            verifier = PKCS1_v1_5.new(public_key)
                # Canonical JSON: keys sorted, compact separators
            msg = json.dumps(transaction, sort_keys=True, separators=(',', ':')).encode('utf8')
            h = SHA.new(msg)




            verifier.verify(h, binascii.unhexlify(signature))
            return True
        except (ValueError, TypeError, binascii.Error):
            return False


    @staticmethod
    def valid_proof(transactions, last_hash, nonce, difficulty=MINING_DIFFICULTY):
        guess = (str(transactions) + str(last_hash) + str(nonce)).encode('utf8')
        h = hashlib.new('sha256')
        h.update(guess)
        guess_hash = h.hexdigest()
        return guess_hash[:difficulty] == '0' * difficulty

    def proof_of_work(self):
        last_block = self.chain[-1]
        last_hash = self.hash(last_block)
        nonce = 0
        while self.valid_proof(self.transactions, last_hash, nonce) is False:
            nonce += 1
        return nonce

    @staticmethod
    def hash(block):
        block_string = json.dumps(block, sort_keys=True).encode('utf8')
        h = hashlib.new('sha256')
        h.update(block_string)
        return h.hexdigest()

    def resolve_conflicts(self):
        neighbours = self.nodes
        new_chain = None
        max_length = len(self.chain)
        for node in neighbours:
            try:
                response = requests.get('http://' + node + '/chain')
            except requests.exceptions.RequestException:
                continue

            if response.status_code == 200:
                length = response.json()['length']
                chain = response.json()['chain']
                if length > max_length and self.valid_chain(chain):
                    max_length = length
                    new_chain = chain
        if new_chain:
            self.chain = new_chain
            return True
        return False

    def valid_chain(self, chain):
        last_block = chain[0]
        current_index = 1
        while current_index < len(chain):
            block = chain[current_index]
            if block['previous_hash'] != self.hash(last_block):
                return False
            transactions = block['transactions'][:-1] if len(block['transactions']) > 0 else []
            transaction_elements = ['librarian_public_key', 'student_id', 'book_id', 'action']
            try:
                transactions = [OrderedDict((k, transaction[k]) for k in transaction_elements) for transaction in transactions]
            except Exception:
                return False
            if not self.valid_proof(transactions, block['previous_hash'], block['nonce'], MINING_DIFFICULTY):
                return False
            last_block = block
            current_index += 1
        return True

    def submit_transaction(self, librarian_public_key, student_id, book_id, action, signature):
        transaction = OrderedDict({
            'librarian_public_key': librarian_public_key,
            'student_id': student_id,
            'book_id': book_id,
            'action': action
        })
        if librarian_public_key == MINING_SENDER:
            self.transactions.append(transaction)
            return len(self.chain) + 1
        else:
            signature_verification = self.verify_transaction_signature(librarian_public_key, signature, transaction)
            if signature_verification:
                self.transactions.append(transaction)
                return len(self.chain) + 1
            else:
                return False


blockchain = Blockchain()
app = Flask(__name__)
CORS(app)


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/configure')
def configure():
    return render_template('configure.html')


@app.route('/transactions/get', methods=['GET'])
def get_transactions():
    transactions = blockchain.transactions
    response = {'transactions': transactions}
    return jsonify(response), 200


@app.route('/chain', methods=['GET'])
def get_chain():
    response = {
        'chain': blockchain.chain,
        'length': len(blockchain.chain)
    }
    return jsonify(response), 200


@app.route('/mine', methods=['GET'])
def mine():
    nonce = blockchain.proof_of_work()
    blockchain.submit_transaction(librarian_public_key=MINING_SENDER,
                                  student_id='',
                                  book_id='',
                                  action='reward',
                                  signature='')
    last_block = blockchain.chain[-1]
    previous_hash = blockchain.hash(last_block)
    block = blockchain.create_block(nonce, previous_hash)
    response = {
        'message': 'New block created',
        'block_number': block['block_number'],
        'transactions': block['transactions'],
        'nonce': block['nonce'],
        'previous_hash': block['previous_hash'],
    }
    return jsonify(response), 200


@app.route('/transactions/new', methods=['POST'])
def new_transaction():
    values = request.form
    required = ['librarian_public_key', 'student_id', 'book_id', 'action', 'transaction_signature']
    if not all(k in values for k in required):
        return 'Missing values', 400

    transaction_results = blockchain.submit_transaction(values['librarian_public_key'],
                                                       values['student_id'],
                                                       values['book_id'],
                                                       values['action'],
                                                       values['transaction_signature'])
    if transaction_results is False:
        response = {'message': 'Invalid transaction/signature'}
        return jsonify(response), 406
    else:
        response = {'message': 'Transaction will be added to the Block ' + str(transaction_results)}
        return jsonify(response), 201


@app.route('/nodes/get', methods=['GET'])
def get_nodes():
    nodes = list(blockchain.nodes)
    response = {'nodes': nodes}
    return jsonify(response), 200


@app.route('/nodes/resolve', methods=['GET'])
def consensus():
    replaced = blockchain.resolve_conflicts()
    if replaced:
        response = {
            'message': 'Our chain was replaced',
            'new_chain': blockchain.chain
        }
    else:
        response = {
            'message': 'Our chain is authoritative',
            'chain': blockchain.chain
        }
    return jsonify(response), 200


@app.route('/nodes/register', methods=['POST'])
def register_node():
    values = request.form
    nodes = values.get('nodes')
    if not nodes:
        return 'Error: Please supply a valid list of nodes', 400

    nodes = nodes.replace(' ', '').split(',')

    for node in nodes:
        blockchain.register_node(node)

    response = {
        'message': 'Nodes have been added',
        'total_nodes': list(blockchain.nodes)
    }
    return jsonify(response), 200


if __name__ == '__main__':
    from argparse import ArgumentParser
    parser = ArgumentParser()
    parser.add_argument('-p', '--port', default=5001, type=int, help="port to listen to")
    args = parser.parse_args()
    port = args.port
    app.run(host='127.0.0.1', port=port, debug=True)
