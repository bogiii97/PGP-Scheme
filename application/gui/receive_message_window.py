import hashlib
import os
import base64
import zlib

from PyQt5.QtCore import pyqtSignal
from PyQt5.QtWidgets import QFileDialog, QMessageBox, QWidget, QPushButton, QVBoxLayout, QHBoxLayout
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

from application.util import convertPublicToPEM


class ReceiveMessageWindow(QWidget):
    switch_to_menu = pyqtSignal(str)  # Signal za vraćanje na meni

    def __init__(self, user, users):
        super().__init__()
        self.user = user
        self.users = users
        self.message = ""
        self.selected_options = []
        self.selected_algorithm = ""

        self.setWindowTitle('Prijem poruke')
        self.setFixedSize(300, 200)
        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout()

        self.back_button = QPushButton('Nazad na meni', self)
        self.back_button.clicked.connect(self.back_to_menu)
        layout.addWidget(self.back_button)

        button_layout = QHBoxLayout()
        self.import_button = QPushButton('Procitaj poruku', self)
        self.import_button.setFixedWidth(150)
        self.import_button.clicked.connect(self.receive_message)
        button_layout.addStretch()
        button_layout.addWidget(self.import_button)
        button_layout.addStretch()
        layout.addLayout(button_layout)

        self.setLayout(layout)

    def back_to_menu(self):
        self.switch_to_menu.emit(self.user.email)

    def receive_message(self):
        user_folder_path = os.path.join("..\\keyPairs", self.user.email, "inbox")
        options = QFileDialog.Options()
        file_name, _ = QFileDialog.getOpenFileName(self, "Odaberite poruku", user_folder_path,
                                                   "Text Files (*.txt);;All Files (*)", options=options)

        if file_name:
            try:
                with open(file_name, 'r') as file:
                    flags_line = file.readline().strip()
                    flags = flags_line.split(',')

                    # Map flags to options
                    flag_to_option = {
                        "0": "Autentikacija",
                        "1": "Kompresija",
                        "2": "Tajnost",
                        "3": "Radix 64"
                    }

                    # Clear current selected options
                    self.selected_options = []

                    # Update selected options based on flags
                    for flag in flags:
                        if flag in flag_to_option:
                            self.selected_options.append(flag_to_option[flag])

                    # Read the rest of the message
                    message = file.read().strip()

                    # Decode from Radix64 if selected
                    if 'Radix 64' in self.selected_options:
                        M = base64.b64decode(message.encode('utf-8')).decode('utf-8')

                    if 'Tajnost' in self.selected_options:
                        try:
                            parts = message.split('\n')
                            encrypted_message_hex = parts[0]
                            encrypted_session_key_hex = parts[1]
                            receiver_public_key_id = parts[2]  # Make sure it's in bytes

                            print("Receiver public key id from receive side:")
                            print(receiver_public_key_id)

                            encrypted_message = bytes.fromhex(encrypted_message_hex)
                            encrypted_session_key = bytes.fromhex(encrypted_session_key_hex)

                            # Retrieve the sender's private key
                            receiver_private_key = None
                            receiver_public_key = None
                            for user in self.users:
                                if self.user.email != user.email:
                                    continue
                                print("User's public key ids:")
                                for key in user.private_ring:
                                    print(len(key.publicKey.keyID))
                                    print(len(receiver_public_key_id))
                                    print(key.publicKey.keyID)
                                    print(receiver_public_key_id)
                                    if key.publicKey.keyID[:8] == receiver_public_key_id[:8]:  # Compare only the first 8 bytes
                                        receiver_private_key = key.privateKey.key
                                        receiver_public_key = key.publicKey.key
                                        break

                            if receiver_private_key is None:
                                raise ValueError("Receiver's private key not found.")

                            # Decrypt the sender's private key using CAST-128
                            password = "123"
                            sha1 = hashlib.sha1()
                            sha1.update(password.encode('utf-8'))
                            hashed_password = sha1.digest()

                            key = hashed_password[:16]  # CAST-128 uses a 128-bit key
                            iv = hashed_password[:8]
                            cipher = Cipher(algorithms.CAST5(key), modes.CFB(iv), backend=default_backend())
                            decryptor = cipher.decryptor()
                            decrypted_private_key_bytes = decryptor.update(receiver_private_key) + decryptor.finalize()

                            private_key = serialization.load_der_private_key(
                                decrypted_private_key_bytes,
                                password=None,
                                backend=default_backend()
                            )

                            # Decrypt the session key
                            session_key = private_key.decrypt(
                                encrypted_session_key,
                                padding.OAEP(
                                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                    algorithm=hashes.SHA256(),
                                    label=None
                                )
                            )

                            # Decrypt the message
                            if self.selected_algorithm == 'AES-128':
                                iv = receiver_public_key[:16]  # Use appropriate IV extraction
                                key = receiver_public_key[:16]  # AES-128 uses a 128-bit key
                                cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
                            elif self.selected_algorithm == 'Triple DES':
                                iv = receiver_public_key[:8]  # Use appropriate IV extraction
                                key = receiver_public_key[:24]  # Triple DES uses a 192-bit key
                                cipher = Cipher(algorithms.TripleDES(key), modes.CFB(iv), backend=default_backend())
                            else:
                                raise ValueError("Nepodržani algoritam")

                            decryptor = cipher.decryptor()
                            decrypted_message = decryptor.update(encrypted_message) + decryptor.finalize()

                            # Convert decrypted bytes back to string
                            M = decrypted_message.decode('utf-8')
                            print(f"Decrypted Message: {M}")

                        except Exception as e:
                            print(f"Failed to decrypt the message: {e}")

                    # Decompress if selected
                    if 'Kompresija' in self.selected_options:
                        try:
                            message = base64.b64decode(message)  # Decode the base64 encoded compressed message to bytes
                            message = zlib.decompress(message).decode(
                                'utf-8')  # Decompress the bytes and decode to string
                            print("Message decompressed.")
                        except Exception as e:
                            print(f"Failed to decompress message: {e}")

                    # Process other options if needed

                    if 'Autentikacija' in self.selected_options:
                        try:
                            # Extract the signature structure
                            lines = message.split('\n')
                            message_content = '\n'.join(lines[:-3])  # Original message content
                            timestamp = lines[-3]
                            sender_public_key_id = lines[-2]
                            signature = bytes.fromhex(lines[-1])

                            # Retrieve the sender's public key
                            sender_public_key = None
                            for user in self.users:
                                for key in user.public_ring:
                                    if key.publicKey.keyID == sender_public_key_id:
                                        sender_public_key = key.publicKey.key
                                        break

                            if sender_public_key is None:
                                raise ValueError("Sender's public key not found.")

                            sender_public_key = serialization.load_pem_public_key(
                                convertPublicToPEM(sender_public_key).encode('utf-8'),
                                backend=default_backend()
                            )

                            # Verify the signature
                            sender_public_key.verify(
                                signature,
                                hashlib.sha1(message_content.encode('utf-8')).digest(),
                                padding.PKCS1v15(),
                                hashes.SHA1()
                            )
                            print("Message is authentic.")
                        except Exception as e:
                            print(f"Failed to verify message authenticity: {e}")

                    print(f"Final Message: {message}")


            except Exception as e:
                print(f"Greška prilikom čitanja fajla: {e}")

                """ if 'Radix 64' in self.selected_options:
                                        try:
                                            message = base64.b64decode(message)
                                            print("Message decoded from Radix64.")
                                        except Exception as e:
                                            print(f"Failed to decode from Radix64: {e}")

                                    # Decrypt if 'Tajnost' is selected
                                    if 'Tajnost' in self.selected_options:
                                        try:
                                            # Split the message to extract components
                                            message = message.decode('utf-8')
                                            components = message.split('\n')

                                            receiver_public_key_id = components[0]

                                            encrypted_session_key = components[1]

                                            iv = components[2]

                                            encrypted_message = components[3]

                                            # Find the corresponding private key in the user's private ring
                                            private_key_info = None
                                            print("Usao")
                                            for key in self.user.private_ring:
                                                if key.publicKey.keyID == receiver_public_key_id:
                                                    private_key_info = key.privateKey.key
                                                    break
                                            print("Usao1")
                                            if private_key_info is None:
                                                raise ValueError("Private key not found for the given public key ID.")

                                            # Decrypt the private key using CAST-128
                                            password = "123"
                                            sha1 = hashlib.sha1()
                                            sha1.update(password.encode('utf-8'))
                                            hashed_password = sha1.digest()

                                            key = hashed_password[:16]  # CAST-128 uses a 128-bit key
                                            iv_private = private_key_info.privateKey.key[:8]  # Extract the first 8 bytes as IV
                                            encrypted_private_key = private_key_info.privateKey.key[8:]
                                            print("Usao2")
                                            cipher = Cipher(algorithms.CAST5(key), modes.CFB(iv_private), backend=default_backend())
                                            decryptor = cipher.decryptor()
                                            private_byte = decryptor.update(encrypted_private_key) + decryptor.finalize()
                                            print("Usao3")
                                            # Load the private key
                                            private_key = serialization.load_der_private_key(
                                                private_byte,
                                                password=None,
                                                backend=default_backend()
                                            )
                                            print("Usao4")
                                            # Decrypt the session key with the receiver's private key
                                            session_key = private_key.decrypt(
                                                encrypted_session_key,
                                                padding.OAEP(
                                                    mgf=padding.MGF1(algorithm=hashes.SHA1()),
                                                    algorithm=hashes.SHA1(),
                                                    label=None
                                                )
                                            )
                                            print("Usao5")
                                            # Decrypt the message with the session key
                                            if self.selected_algorithm == 'Triple DES':
                                                cipher_algorithm = algorithms.TripleDES(session_key)
                                            elif self.selected_algorithm == 'AES-128':
                                                cipher_algorithm = algorithms.AES(session_key)
                                            else:
                                                raise ValueError("Unsupported algorithm selected")

                                            cipher = Cipher(cipher_algorithm, modes.CFB(iv), backend=default_backend())
                                            decryptor = cipher.decryptor()
                                            message = decryptor.update(encrypted_message) + decryptor.finalize()
                                            message = message.decode('utf-8')
                                            print("Message decrypted with session key.")
                                        except Exception as e:
                                            print(f"Failed to decrypt message: {e}")"""
