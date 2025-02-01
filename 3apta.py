import time
import hashlib
import tkinter as tk
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization

# Қарапайым хэш функциясы
def simple_hash(data):
    return int(hashlib.sha256(data.encode('utf-8')).hexdigest(), 16)

# Блок құрылымы
class Block:
    def __init__(self, index, data, previous_hash='', transactions=[]):
        self.index = index
        self.timestamp = time.time()  # Уақыт белгісі
        self.data = data
        self.previous_hash = previous_hash  # Алдыңғы блоктың хэш адресі
        self.transactions = transactions  # Транзакциялар
        self.merkle_root = self.calculate_merkle_root([tx['tx_hash'] for tx in transactions])  # Меркле түбірін есептеу
        self.hash = self.calculate_hash()  # Блоктың хэшін есептеу

    def calculate_hash(self):
        # Блоктың хэшін есептеу
        return simple_hash(f"{self.index}{self.timestamp}{self.data}{self.previous_hash}{self.merkle_root}")

    def calculate_merkle_root(self, tx_hashes):
        # Меркле түбірін есептеу
        if len(tx_hashes) % 2 != 0:
            tx_hashes.append(tx_hashes[-1])  # Егер транзакциялар тақ болса, соңғы элементті қосамыз
        while len(tx_hashes) > 1:
            tx_hashes = [simple_hash(str(tx_hashes[i]) + str(tx_hashes[i + 1])) for i in
                         range(0, len(tx_hashes), 2)]  # Хэш есептеу үшін бүтін санды жолға түрлендіреміз
        return tx_hashes[0]


# Блокчейн құрылымы
class Blockchain:
    def __init__(self):
        self.chain = [self.create_genesis_block()]  # Генезис блокты жасау
        self.utxos = {}

    def create_genesis_block(self):
        # Генезис блокта 3 транзакция қосамыз
        tx1 = {'sender': 'genesis', 'receiver': 'user1', 'amount': 50, 'tx_hash': simple_hash("genesis_transaction_1")}
        tx2 = {'sender': 'user1', 'receiver': 'user2', 'amount': 30, 'tx_hash': simple_hash("genesis_transaction_2")}
        tx3 = {'sender': 'user2', 'receiver': 'user3', 'amount': 20, 'tx_hash': simple_hash("genesis_transaction_3")}
        return Block(0, "Genesis Block", "0", [tx1, tx2, tx3])  # Генезис блокқа 3 транзакция қосамыз

    def add_block(self, data, transactions):
        # Жаңа блок қосу
        new_block = Block(len(self.chain), data, self.chain[-1].hash, transactions)
        self.chain.append(new_block)

    def validate_chain(self):
        # Блокчейннің дұрыс екенін тексеру
        for i in range(1, len(self.chain)):
            if self.chain[i].previous_hash != self.chain[i - 1].hash:
                return False
        return True

    def add_transaction(self, sender, receiver, amount):
        # Транзакция қосу
        tx_hash = simple_hash(f"{sender}{receiver}{amount}")
        self.utxos[tx_hash] = amount
        return {'sender': sender, 'receiver': receiver, 'amount': amount, 'tx_hash': tx_hash}

# Цифрлық қолтаңба (Асимметриялық шифрлау)
class DigitalSignature:
    def __init__(self):
        self.private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.public_key = self.private_key.public_key()

    def sign(self, data):
        # Мәліметтерді қолтаңбалау
        return self.private_key.sign(
            data.encode('utf-8'),
            padding.PKCS1v15(),
            hashes.SHA256()
        )

    def verify(self, data, signature):
        # Қолтаңбаны тексеру
        self.public_key.verify(
            signature,
            data.encode('utf-8'),
            padding.PKCS1v15(),
            hashes.SHA256()
        )

# Кошелек GUI интерфейсі
class WalletGUI:
    def __init__(self, root, blockchain):
        self.root = root
        self.blockchain = blockchain
        self.wallet = DigitalSignature()
        self.balance = 100  # Бастапқы баланс
        self.balance_label = tk.Label(root, text=f"Balance: {self.balance}")
        self.balance_label.pack()

        self.send_button = tk.Button(root, text="Send Transaction", command=self.send_transaction)
        self.send_button.pack()

    def send_transaction(self):
        # Транзакция жіберу
        sender = 'sender_address'
        receiver = 'receiver_address'
        amount = 50
        transaction = self.blockchain.add_transaction(sender, receiver, amount)
        signature = self.wallet.sign(f"{sender}{receiver}{amount}")

        self.blockchain.add_block("Block with Transactions", [transaction])
        self.balance -= amount  # Балансын төмендету
        self.balance_label.config(text=f"Balance: {self.balance}")

        print(f"Transaction sent: {transaction}")
        print(f"Signature: {signature.hex()}")

# Блокчейн зерттеуші интерфейсі
class BlockchainExplorer:
    def __init__(self, root, blockchain):
        self.root = root
        self.blockchain = blockchain
        self.display_blocks()

    def display_blocks(self):
        # Блоктарды көрсету
        for block in self.blockchain.chain:
            block_info = f"Block {block.index} - Hash: {block.hash} - Timestamp: {block.timestamp} - Data: {block.data} - Merkle Root: {block.merkle_root}"
            tk.Label(self.root, text=block_info).pack()

# Негізгі бағдарлама
if __name__ == '__main__':
    # Блокчейн құру
    blockchain = Blockchain()

    # GUI интерфейсін орнату
    root = tk.Tk()
    explorer = BlockchainExplorer(root, blockchain)
    wallet_gui = WalletGUI(root, blockchain)

    # GUI циклі
    root.mainloop()
