import os
import json
from collections import OrderedDict
from flask import Flask, render_template, request, jsonify
import Crypto
import Crypto.Random
from Crypto.PublicKey import RSA
import binascii
from Crypto.Signature import PKCS1_v1_5
from Crypto.Hash import SHA
from datetime import datetime


app = Flask(__name__, template_folder='templates')


class LendingTransaction:
    """
    Represents a book lending transaction
    """
    def __init__(self, student_id, book_id, action, sender_public_key=None, sender_private_key=None):
        self.student_id = student_id
        self.book_id = book_id
        self.action = action
        # keep timestamp for display/record, but do NOT include in the signed payload
        self.timestamp = datetime.utcnow().timestamp()
        self.sender_public_key = sender_public_key
        self.sender_private_key = sender_private_key

    def to_dict(self):
        """Full transaction representation (for UI/display)."""
        return OrderedDict({
            'student_id': self.student_id,
            'book_id': self.book_id,
            'action': self.action,
            'timestamp': self.timestamp,
            'sender_public_key': self.sender_public_key
        })

    def _payload_for_signing(self):
        """
        Canonical payload used for signing & verification.
        IMPORTANT: must match server-side canonicalization exactly (json dumps with sort_keys=True and separators).
        We DO NOT include timestamp here to avoid variability.
        """
        payload = OrderedDict([
            ('sender_public_key', self.sender_public_key),
            ('student_id', self.student_id),
            ('book_id', self.book_id),
            ('action', self.action)
        ])
        return payload

    def sign_transaction(self):
        """
        Sign the canonical JSON payload using the sender's private key.
        Returns hex-encoded signature string, or None if no private key available.
        """
        if not self.sender_private_key:
            return None
        try:
            private_key = RSA.importKey(binascii.unhexlify(self.sender_private_key))
            signer = PKCS1_v1_5.new(private_key)
            payload = self._payload_for_signing()
            # deterministic serialization
            msg = json.dumps(payload, sort_keys=True, separators=(',', ':')).encode('utf8')
            h = SHA.new(msg)
            signature = signer.sign(h)
            return binascii.hexlify(signature).decode('ascii')
        except (ValueError, TypeError, binascii.Error) as e:
            # you may want to log this in a real app
            return None


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/make/transaction')
def make_transaction():
    return render_template('make_transaction.html')


@app.route('/view/transactions')
def view_transactions():
    return render_template('view_transactions.html')


@app.route('/generate/transaction', methods=['POST'])
def generate_transaction():
    student_id = request.form.get('student_id')
    book_id = request.form.get('book_id')
    action = request.form.get('action')
    sender_public_key = request.form.get('sender_public_key')
    sender_private_key = request.form.get('sender_private_key')

    if not student_id or not book_id or action not in ('borrow', 'return'):
        return jsonify({'error': 'student_id, book_id and action (borrow|return) are required'}), 400

    tx = LendingTransaction(student_id, book_id, action, sender_public_key, sender_private_key)
    signature = tx.sign_transaction()

    # return the UI-friendly transaction (with timestamp) and also the exact signed payload for debugging/demo
    response = {
        'transaction': tx.to_dict(),
        'signed_payload': json.dumps(tx._payload_for_signing(), sort_keys=True, separators=(',', ':')),
        'signature': signature
    }
    return jsonify(response), 200


@app.route('/wallet/new')
def new_wallet():
    random_gen = Crypto.Random.new().read
    # increase key size to 2048 bits
    private_key = RSA.generate(2048, random_gen)
    public_key = private_key.publickey()
    response = {
        'private_key': binascii.hexlify(private_key.exportKey('DER')).decode('ascii'),
        'public_key': binascii.hexlify(public_key.exportKey('DER')).decode('ascii')
    }
    return jsonify(response), 200


if __name__ == '__main__':
    from argparse import ArgumentParser
    parser = ArgumentParser()
    parser.add_argument('-p', '--port', default=5000, type=int, help='port to listen on')
    args = parser.parse_args()
    app.run(host='0.0.0.0', port=args.port, debug=True)
