from PyQt5.QtWidgets import QWidget, QVBoxLayout, QLabel, QRadioButton, QPushButton, QButtonGroup, QMessageBox, QLineEdit
from application.algorithms.RSA import generate_keys, convertToPem
from application.models.privateRingRow import  PrivateRingRow
from application.keys.private_key import PrivateKey
from application.keys.public_key import PublicKey
from datetime import datetime
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
import hashlib
import os, base64
class GenerateKeysWindow(QWidget):
    def __init__(self, user):
        super().__init__()
        self.setWindowTitle('Generate Keys')
        self.user = user
        self.key_size = None
        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout()

        self.label = QLabel('Izaberi veličinu ključa:', self)
        layout.addWidget(self.label)

        self.radio_button_group = QButtonGroup(self)

        self.radio_button_1024 = QRadioButton('1024', self)
        self.radio_button_group.addButton(self.radio_button_1024)
        layout.addWidget(self.radio_button_1024)

        self.radio_button_2048 = QRadioButton('2048', self)
        self.radio_button_group.addButton(self.radio_button_2048)
        layout.addWidget(self.radio_button_2048)

        self.password_input = QLineEdit(self)
        self.password_input.setPlaceholderText('Unesite lozinku')
        self.password_input.setEchoMode(QLineEdit.Password)
        layout.addWidget(self.password_input)

        self.submit_button = QPushButton('Generiši', self)
        self.submit_button.clicked.connect(self.submit)
        layout.addWidget(self.submit_button)

        self.setLayout(layout)

    def submit(self):
        selected_button = self.radio_button_group.checkedButton()
        password = self.password_input.text()
        if selected_button and password:
            self.key_size = selected_button.text()

            rsa_private, rsa_public = generate_keys(self.key_size)

            private_byte = rsa_private.private_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )

            public_byte = rsa_public.public_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )


            sha1 = hashlib.sha1()
            sha1.update(password.encode('utf-8'))
            hashed_password = sha1.digest()

            # Encrypt the private key using CAST-128
            key = hashed_password[:16]  # CAST-128 uses a 128-bit key
            iv = os.urandom(8)  # CAST-128 uses a 64-bit IV
            cipher = Cipher(algorithms.CAST5(key), modes.CFB(iv), backend=default_backend())
            encryptor = cipher.encryptor()
            encrypted_private_key = encryptor.update(private_byte) + encryptor.finalize()

            # Extract the lowest 64 bits from the public key
            lowest_64_bits_bytes = public_byte[-8:]
            base64.b64encode(lowest_64_bits_bytes).decode('utf-8')
            public_id_pem = f"-----BEGIN PUBLIC ID-----\n{lowest_64_bits_bytes}\n-----END PUBLIC ID-----\n"

            private_key = PrivateKey(private_byte, encrypted_private_key, password)
            public_key = PublicKey(public_byte, public_id_pem)
            private_ring_row = PrivateRingRow(datetime.now(), public_key, private_key, self.user.email)

            self.user.private_ring.append(private_ring_row)

            convertToPem(private_byte, public_byte, lowest_64_bits_bytes)


            QMessageBox.information(self, 'Generisanje ključa', 'Uspešno ste kreirali ključ')

            # vracanje na show menu
        elif not selected_button:
            QMessageBox.warning(self, 'Greška', 'Molimo vas da izaberete veličinu ključa.')
        elif not password:
            QMessageBox.warning(self, 'Greška', 'Molimo vas da unesete lozinku.')

