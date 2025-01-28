import time
import hashlib
import tkinter as tk
from tkinter import messagebox

# 1-қадам: Қарапайым қолмен хэш алгоритмі (қауіпсіз емес, тек мысал ретінде)
def manual_hash(data):
    """Қарапайым қолмен хэш функциясы, деректерді хэшке ұқсас жолға түрлендіреді."""
    hash_value = 0
    for char in data:
        hash_value += ord(char)
        hash_value = hash_value % 100000  # Хэш мәнін 5 санға шектеу
    return f"{hash_value:05d}"

# 2-қадам: Блок құрылымы
class Block:
    def __init__(self, timestamp, data, previous_hash):
        self.timestamp = timestamp  # Блоктың уақыт таңбасы
        self.data = data  # Блоктағы деректер
        self.previous_hash = previous_hash  # Алдыңғы блоктың хэші
        self.hash = self.calculate_hash()  # Блоктың өз хэші

    def calculate_hash(self):
        # Блок деректерінен хэш мәнін есептеу
        hash_data = f"{self.timestamp}{self.data}{self.previous_hash}"
        return manual_hash(hash_data)

# 3-қадам: Блокчейн құрылымы
class Blockchain:
    def __init__(self):
        self.chain = [self.create_genesis_block()]  # Блокчейн генезис блогымен басталады

    def create_genesis_block(self):
        return Block(time.time(), "Genesis Block", "0")  # Генезис блогын жасау

    def get_latest_block(self):
        return self.chain[-1]  # Соңғы блокты алу

    def add_block(self, data):
        # Жаңа блокты қосу
        latest_block = self.get_latest_block()
        new_block = Block(time.time(), data, latest_block.hash)
        self.chain.append(new_block)

    def is_chain_valid(self):
        # Блокчейннің жарамдылығын тексеру
        for i in range(1, len(self.chain)):
            current_block = self.chain[i]
            previous_block = self.chain[i - 1]

            if current_block.hash != current_block.calculate_hash():
                return False  # Егер блоктың хэші сәйкес келмесе

            if current_block.previous_hash != previous_block.hash:
                return False  # Егер алдыңғы блоктың хэші сәйкес келмесе

        return True

# 4-қадам: Блок Эксплорер GUI
class BlockExplorer:
    def __init__(self, blockchain):
        self.blockchain = blockchain
        self.root = tk.Tk()
        self.root.title("Block Explorer")  # GUI терезесінің атауы
        self.create_gui()

    def create_gui(self):
        # Блоктар тізімін көрсету үшін Listbox жасау
        self.block_list = tk.Listbox(self.root, width=80, height=20)
        self.block_list.pack(pady=10)

        # Блокчейнді тексеру батырмасын қосу
        validate_button = tk.Button(self.root, text="Validate Blockchain", command=self.validate_chain)
        validate_button.pack(pady=5)

        self.update_block_list()

    def update_block_list(self):
        # Блоктардың тізімін жаңарту
        self.block_list.delete(0, tk.END)
        for i, block in enumerate(self.blockchain.chain):
            block_info = f"Block {i} | Hash: {block.hash} | Timestamp: {time.ctime(block.timestamp)} | Data: {block.data}"
            self.block_list.insert(tk.END, block_info)

    def validate_chain(self):
        # Блокчейннің жарамдылығын тексеру
        if self.blockchain.is_chain_valid():
            messagebox.showinfo("Validation", "Blockchain is valid!")  # Егер жарамды болса
        else:
            messagebox.showerror("Validation", "Blockchain is invalid!")  # Егер жарамсыз болса

# Негізгі орындалу бөлігі
if __name__ == "__main__":
    # Блокчейннің экземплярын жасау
    blockchain = Blockchain()

    # Бірнеше блок қосу
    blockchain.add_block("Block 1 Data")
    blockchain.add_block("Block 2 Data")
    blockchain.add_block("Block 3 Data")

    # Блок Эксплорер GUI іске қосу
    explorer = BlockExplorer(blockchain)
    explorer.root.mainloop()
