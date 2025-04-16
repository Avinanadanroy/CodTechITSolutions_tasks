from PyQt5.QtWidgets import QApplication, QWidget, QPushButton, QVBoxLayout, QFileDialog, QLabel, QLineEdit
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os, base64

def derive_key(password: str, salt: bytes):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

def encrypt_file(file_path, password):
    salt = os.urandom(16)
    key = derive_key(password, salt)
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    
    with open(file_path, 'rb') as f:
        plaintext = f.read()
    
    padding_length = 16 - (len(plaintext) % 16)
    plaintext += bytes([padding_length]) * padding_length
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    
    enc_file = file_path + ".enc"
    with open(enc_file, 'wb') as f:
        f.write(salt + iv + ciphertext)
    
    return enc_file

def decrypt_file(file_path, password):
    with open(file_path, 'rb') as f:
        data = f.read()
    
    salt, iv, ciphertext = data[:16], data[16:32], data[32:]
    key = derive_key(password, salt)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    plaintext_padded = decryptor.update(ciphertext) + decryptor.finalize()
    padding_length = plaintext_padded[-1]
    plaintext = plaintext_padded[:-padding_length]
    
    dec_file = file_path.replace(".enc", "_decrypted")
    with open(dec_file, 'wb') as f:
        f.write(plaintext)
    
    return dec_file

class EncryptionApp(QWidget):
    def __init__(self):
        super().__init__()
        self.init_ui()

    def init_ui(self):
        self.layout = QVBoxLayout()
        self.file_label = QLabel("Select a file")
        self.layout.addWidget(self.file_label)

        self.password_label = QLabel("Enter Password")
        self.layout.addWidget(self.password_label)
        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.Password)
        self.layout.addWidget(self.password_input)

        self.encrypt_button = QPushButton("Encrypt File")
        self.encrypt_button.clicked.connect(self.encrypt)
        self.layout.addWidget(self.encrypt_button)

        self.decrypt_button = QPushButton("Decrypt File")
        self.decrypt_button.clicked.connect(self.decrypt)
        self.layout.addWidget(self.decrypt_button)

        self.setLayout(self.layout)
        self.setWindowTitle("AES-256 File Encryption Tool")

    def select_file(self):
        options = QFileDialog.Options()
        file_path, _ = QFileDialog.getOpenFileName(self, "Select File", "", "All Files (*)", options=options)
        return file_path

    def encrypt(self):
        file_path = self.select_file()
        if file_path:
            enc_file = encrypt_file(file_path, self.password_input.text())
            self.file_label.setText(f"Encrypted: {enc_file}")

    def decrypt(self):
        file_path = self.select_file()
        if file_path:
            dec_file = decrypt_file(file_path, self.password_input.text())
            self.file_label.setText(f"Decrypted: {dec_file}")

if __name__ == "__main__":
    app = QApplication([])
    window = EncryptionApp()
    window.show()
    app.exec_()
