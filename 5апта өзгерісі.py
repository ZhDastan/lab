import time
import json
import hashlib
import requests
import random
import tkinter as tk
from flask import Flask, request, jsonify
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding

# Түйіндер тізімі (декентрализация үшін)
nodes = set()
MINING_REWARD = 50  # Миннинг үшін жүлде
TRANSACTION_FEE = 1  # Әр транзакциядан алынатын комиссия


def simple_hash(data):
    return int(hashlib.sha256(data.encode('utf-8')).hexdigest(), 16)


class Block:
    def __init__(self, index, data, previous_hash='', transactions=[], nonce=0):
        self.index = index
        self.timestamp = time.time()
        self.data = data
        self.previous_hash = previous_hash
        self.transactions = transactions
        self.merkle_root = self.calculate_merkle_root([tx['tx_hash'] for tx in transactions]) if transactions else ""
        self.nonce = nonce
        self.hash = self.calculate_hash()

    def calculate_hash(self):
        return simple_hash(f"{self.index}{self.timestamp}{self.data}{self.previous_hash}{self.merkle_root}{self.nonce}")

    def calculate_merkle_root(self, tx_hashes):
        if len(tx_hashes) % 2 != 0:
            tx_hashes.append(tx_hashes[-1])
        while len(tx_hashes) > 1:
            tx_hashes = [simple_hash(str(tx_hashes[i]) + str(tx_hashes[i + 1])) for i in range(0, len(tx_hashes), 2)]
        return tx_hashes[0]

    def mine_block(self, difficulty, max_nonce=10 ** 6):
        while str(self.hash)[:difficulty] != '0' * difficulty:
            self.nonce += 1
            self.hash = self.calculate_hash()
            if self.nonce >= max_nonce:
                print("Mining aborted: max nonce limit reached")
                break
        print(f"Block mined: {self.hash}")


class Blockchain:
    def __init__(self, difficulty=4):
        self.chain = [self.create_genesis_block()]
        self.utxos = {}
        self.difficulty = difficulty

    def create_genesis_block(self):
        return Block(0, "Genesis Block", "0", [])

    def add_block(self, data, transactions):
        new_block = Block(len(self.chain), data, self.chain[-1].hash, transactions)
        new_block.mine_block(self.difficulty)
        self.chain.append(new_block)

    def validate_chain(self):
        for i in range(1, len(self.chain)):
            if self.chain[i].previous_hash != self.chain[i - 1].hash:
                return False
        return True

    def add_transaction(self, sender, receiver, amount):
        tx_hash = simple_hash(f"{sender}{receiver}{amount}")
        self.utxos[tx_hash] = {'sender': sender, 'receiver': receiver, 'amount': amount, 'tx_hash': tx_hash}
        return self.utxos[tx_hash]

    def mine_transactions(self, miner_address):
        transactions = list(self.utxos.values())
        reward_transaction = {'sender': 'network', 'receiver': miner_address, 'amount': MINING_REWARD,
                              'tx_hash': simple_hash(f"reward{miner_address}{time.time()}")}
        transactions.append(reward_transaction)
        self.add_block("Mining Reward Block", transactions)


# Түйіндерді басқару функциялары
def register_node(node_url):
    nodes.add(node_url)


def get_nodes():
    return list(nodes)


def sync_blockchain():
    longest_chain = None
    max_length = len(blockchain.chain)

    for node in nodes:
        try:
            response = requests.get(f"{node}/chain")
            length = response.json()['length']
            chain = response.json()['chain']

            if length > max_length and Blockchain.validate_chain_static(chain):
                max_length = length
                longest_chain = chain
        except:
            continue

    if longest_chain:
        blockchain.chain = longest_chain
        return True
    return False


class DigitalSignature:
    def __init__(self):
        self.private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.public_key = self.private_key.public_key()

    def sign(self, data):
        return self.private_key.sign(data.encode('utf-8'), padding.PKCS1v15(), hashes.SHA256())

    def verify(self, data, signature):
        self.public_key.verify(signature, data.encode('utf-8'), padding.PKCS1v15(), hashes.SHA256())


class WalletGUI:
    def __init__(self, root, blockchain):
        self.root = root
        self.blockchain = blockchain
        self.wallet = DigitalSignature()
        self.balance = 5000
        self.balance_label = tk.Label(root, text=f"Balance: {self.balance}")
        self.balance_label.pack()
        self.send_button = tk.Button(root, text="Send Transaction", command=self.send_transaction)
        self.send_button.pack()
        self.mine_button = tk.Button(root, text="Mine Block", command=self.mine_block)
        self.mine_button.pack()

    def send_transaction(self):
        sender = 'sender_address'
        receiver = 'receiver_address'
        amount = 100
        transaction = self.blockchain.add_transaction(sender, receiver, amount)
        self.balance -= amount + TRANSACTION_FEE
        self.balance_label.config(text=f"Balance: {self.balance}")
        print(f"Transaction sent: {transaction}")

    def mine_block(self):
        self.blockchain.mine_transactions('miner_address')
        print("Block mined and reward received!")


app = Flask(__name__)
blockchain = Blockchain()


@app.route("/mine", methods=["GET"])
def mine():
    blockchain.mine_transactions('miner_address')
    return jsonify({"message": "Block mined successfully!"}), 200


@app.route("/nodes/register", methods=["POST"])
def register_nodes():
    values = request.get_json()
    for node in values.get("nodes", []):
        register_node(node)
    return jsonify({"message": "Nodes registered", "total_nodes": get_nodes()}), 201


@app.route("/nodes", methods=["GET"])
def get_registered_nodes():
    return jsonify({"nodes": get_nodes()}), 200


if __name__ == "__main__":
    root = tk.Tk()
    root.title("Blockchain Network")
    wallet_gui = WalletGUI(root, blockchain)
    root.mainloop()
    app.run(port=5000)
