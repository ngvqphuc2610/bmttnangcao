from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
import base64
import os

class RSACipher:
    def __init__(self, key_size=2048):
        self.key_size = key_size
        self.private_key = None
        self.public_key = None
        self.load_or_generate_keys()

    def load_or_generate_keys(self):
        """Tải hoặc tạo cặp khóa RSA"""
        if os.path.exists("private.pem") and os.path.exists("public.pem"):
            with open("private.pem", "rb") as priv_file:
                self.private_key = RSA.import_key(priv_file.read())
            with open("public.pem", "rb") as pub_file:
                self.public_key = RSA.import_key(pub_file.read())
        else:
            self.generate_keys()

    def generate_keys(self):
        """Tạo và lưu cặp khóa RSA"""
        key = RSA.generate(self.key_size)
        self.private_key = key
        self.public_key = key.publickey()

        with open("private.pem", "wb") as priv_file:
            priv_file.write(self.private_key.export_key())
        with open("public.pem", "wb") as pub_file:
            pub_file.write(self.public_key.export_key())

    def encrypt(self, message):
        """Mã hóa tin nhắn bằng khóa công khai"""
        cipher = PKCS1_OAEP.new(self.public_key)
        encrypted_message = cipher.encrypt(message.encode())
        return base64.b64encode(encrypted_message).decode()

    def decrypt(self, cipher_text):
        """Giải mã tin nhắn bằng khóa riêng"""
        cipher = PKCS1_OAEP.new(self.private_key)
        decrypted_message = cipher.decrypt(base64.b64decode(cipher_text))
        return decrypted_message.decode()

    def sign(self, message):
        """Tạo chữ ký số cho tin nhắn"""
        hash_msg = SHA256.new(message.encode())
        signature = pkcs1_15.new(self.private_key).sign(hash_msg)
        return base64.b64encode(signature).decode()

    def verify(self, message, signature):
        """Xác minh chữ ký số"""
        hash_msg = SHA256.new(message.encode())
        try:
            pkcs1_15.new(self.public_key).verify(hash_msg, base64.b64decode(signature))
            return "Signature is valid"
        except (ValueError, TypeError):
            return "Signature is invalid"

# Test code nếu chạy trực tiếp file này
if __name__ == "__main__":
    rsa = RSACipher()
    msg = "Hello, RSA!"

    # Mã hóa & Giải mã
    encrypted = rsa.encrypt(msg)
    decrypted = rsa.decrypt(encrypted)

    # Ký & Xác minh
    signature = rsa.sign(msg)
    verification = rsa.verify(msg, signature)

    print("Original:", msg)
    print("Encrypted:", encrypted)
    print("Decrypted:", decrypted)
    print("Signature:", signature)
    print("Verification:", verification)