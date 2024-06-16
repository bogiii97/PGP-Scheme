import hashlib
import os
import base64
import zlib

from PyQt5.QtCore import pyqtSignal
from PyQt5.QtWidgets import QFileDialog, QMessageBox, QWidget, QPushButton, QVBoxLayout, QHBoxLayout, QLineEdit, QLabel
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

from application.util import convertPublicToPEM


class ReceiveMessageWindow(QWidget):
    switch_to_menu = pyqtSignal(str)

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
        self.layout = QVBoxLayout()

        self.back_button = QPushButton('Nazad na meni', self)
        self.back_button.clicked.connect(self.back_to_menu)
        self.layout.addWidget(self.back_button)

        button_layout = QHBoxLayout()
        self.import_button = QPushButton('Učitaj poruku', self)
        self.import_button.setFixedWidth(150)
        self.import_button.clicked.connect(self.receive_message)
        button_layout.addStretch()
        button_layout.addWidget(self.import_button)
        button_layout.addStretch()
        self.layout.addLayout(button_layout)

        self.password_input = QLineEdit(self)
        self.password_input.setPlaceholderText("Unesite lozinku")
        self.password_input.setEchoMode(QLineEdit.Password)
        self.password_input.hide()
        self.layout.addWidget(self.password_input)

        read_button_layout = QHBoxLayout()
        self.read_button = QPushButton('Pročitaj poruku', self)
        self.read_button.setFixedWidth(150)
        self.read_button.clicked.connect(self.read_message)
        self.read_button.hide()
        read_button_layout.addStretch()
        read_button_layout.addWidget(self.read_button)
        read_button_layout.addStretch()
        self.layout.addLayout(read_button_layout)

        self.message_label = QLabel('', self)
        self.layout.addWidget(self.message_label)
        self.sender_label = QLabel('', self)
        self.layout.addWidget(self.sender_label)

        self.setLayout(self.layout)

    def back_to_menu(self):
        self.switch_to_menu.emit(self.user.email)

    def read_message(self):
        if 'Tajnost' in self.selected_options and not self.password_input.text():
            QMessageBox.warning(self, 'Upozorenje', 'Morate uneti lozinku za dešifrovanje.')
            return

        if 'Radix 64' in self.selected_options:
            try:
                self.M = base64.b64decode(self.M.encode('utf-8')).decode('utf-8')
            except:
                print("Neuspela Radix 64 dekripcija")
                return
        if 'Tajnost' in self.selected_options:
            try:
                parts = self.M.split('\n')
                encrypted_message_hex = parts[0]
                encrypted_session_key_hex = parts[1]
                receiver_public_key_id_hex = parts[2]

                encrypted_message = bytes.fromhex(encrypted_message_hex)
                encrypted_session_key = bytes.fromhex(encrypted_session_key_hex)
                receiver_public_key_id = bytes.fromhex(receiver_public_key_id_hex)


                receiver_private_key = None

                for key in self.user.private_ring:
                    if key.publicKey.keyID == receiver_public_key_id:
                        receiver_private_key = key.privateKey.key
                        break

                if receiver_private_key is None:
                    print("Receiver's private key not found.")
                    return


                password = self.password_input.text()
                sha1 = hashlib.sha1()
                sha1.update(password.encode('utf-8'))
                hashed_password = sha1.digest()

                key = hashed_password[:16]
                iv = hashed_password[:8]
                cipher = Cipher(algorithms.CAST5(key), modes.CFB(iv), backend=default_backend())
                decryptor = cipher.decryptor()
                decrypted_private_key_bytes = decryptor.update(receiver_private_key) + decryptor.finalize()

                try:
                    private_key = serialization.load_der_private_key(
                        decrypted_private_key_bytes,
                        password=None,
                        backend=default_backend()
                    )
                except Exception as e:
                    QMessageBox.warning(self, 'Pogrešna lozinka', 'Uneli ste neispravnu lozinku, pokušajte ponovo.')
                    return

                try:
                    session_key = private_key.decrypt(
                        encrypted_session_key,
                        padding.OAEP(
                            mgf=padding.MGF1(algorithm=hashes.SHA256()),
                            algorithm=hashes.SHA256(),
                            label=None
                        )
                    )
                except Exception as e:
                    print("Neuspešno dekriptovan sesijski ključ")
                    return

                if self.selected_algorithm == 'AES-128':
                    iv = session_key[:16]
                    key = session_key[:16]
                    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
                elif self.selected_algorithm == 'Triple DES':
                    iv = session_key[:8]
                    key = session_key[:24]
                    cipher = Cipher(algorithms.TripleDES(key), modes.CFB(iv), backend=default_backend())
                else:
                    raise ValueError("Nepodržani algoritam")

                try:
                    decryptor = cipher.decryptor()
                    decrypted_message = decryptor.update(encrypted_message) + decryptor.finalize()
                except Exception as e:
                    print("Neuspešno dešifrovana poruka")

                self.M = decrypted_message.decode('utf-8')


            except Exception as e:
                print(f"Failed to decrypt the message: {e}")


        if 'Kompresija' in self.selected_options:
            try:
                self.M = base64.b64decode(self.M)
                self.M = zlib.decompress(self.M).decode(
                    'utf-8')
            except Exception as e:
                print(f"Failed to decompress message: {e}")


        if 'Autentikacija' in self.selected_options:
            try:
                lines = self.M.split('\n')
                message_content = '\n'.join(lines[:-3])
                timestamp = lines[-3]
                sender_public_key_id = bytes.fromhex(lines[-2])
                signature = bytes.fromhex(lines[-1])

                sender_public_key = None
                for key in self.user.public_ring:
                    if key.publicKey.keyID == sender_public_key_id:
                        sender_public_key = key.publicKey.key
                        break

                if sender_public_key is None:
                    print("Sender's public key not found.")
                    return

                sender_public_key = serialization.load_pem_public_key(
                    convertPublicToPEM(sender_public_key).encode('utf-8'),
                    backend=default_backend()
                )

                sender_public_key.verify(
                    signature,
                    hashlib.sha1(message_content.encode('utf-8')).digest(),
                    padding.PKCS1v15(),
                    hashes.SHA1()
                )
            except Exception as e:
                errorMessage = "Failed to verify message"

        message = self.M.split('\n')[0]
        sender = self.M.split('\n')[3]
        self.message_label.setText(f"Poruka: {message}")
        self.sender_label.setText(f"Od: {sender}")

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


                    flag_to_option = {
                        "0": "Autentikacija",
                        "1": "Kompresija",
                        "2": "Tajnost",
                        "3": "Radix 64",
                        "4": "Triple DES",
                        "5": "AES-128"
                    }


                    self.selected_options = []


                    for flag in flags:
                        if flag in flag_to_option:
                            self.selected_options.append(flag_to_option[flag])
                    if 'Triple DES' in self.selected_options:
                        self.selected_algorithm = "Triple DES"
                    if 'AES-128' in self.selected_options:
                        self.selected_algorithm = "AES-128"




                    self.M = file.read().strip()

                    if 'Tajnost' in self.selected_options:
                        self.password_input.show()


                    self.read_button.show()

            except Exception as e:
                print(f"Greška prilikom čitanja fajla: {e}")

    def convertPublicToPEM(public_key):
        # Assuming public_key is a bytes object containing the DER-encoded public key
        pem = serialization.load_der_public_key(public_key, backend=default_backend()).public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        return pem.decode('utf-8')
