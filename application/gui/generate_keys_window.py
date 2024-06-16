from PyQt5.QtWidgets import QWidget, QVBoxLayout, QLabel, QRadioButton, QPushButton, QButtonGroup, QMessageBox, QLineEdit
from PyQt5.QtCore import pyqtSignal
from application.algorithms.RSA import generate_keys
from application.models.privateRingRow import PrivateRingRow
from application.keys.private_key import PrivateKey
from application.keys.public_key import PublicKey
from datetime import datetime
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import hashlib
import os
from application.util import *

class GenerateKeysWindow(QWidget):
    switch_to_menu = pyqtSignal(object)

    def __init__(self, user):
        super().__init__()
        self.setWindowTitle('Generisanje ključeva')
        self.user = user
        self.key_size = None
        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout()

        self.back_button = QPushButton('Nazad na meni', self)
        self.back_button.clicked.connect(self.back_to_menu)
        layout.addWidget(self.back_button)

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

    def back_to_menu(self):
        self.switch_to_menu.emit(self.user.email)

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



            key = hashed_password[:16]
            iv = hashed_password[:8]
            cipher = Cipher(algorithms.CAST5(key), modes.CFB(iv), backend=default_backend())
            encryptor = cipher.encryptor()
            encrypted_private_key = encryptor.update(private_byte) + encryptor.finalize()


            lowest_64_bits_bytes = public_byte[-8:]

            private_key = PrivateKey(encrypted_private_key)
            public_key = PublicKey(public_byte, lowest_64_bits_bytes)
            private_ring_row = PrivateRingRow(datetime.now(), public_key, private_key, self.user.email)

            self.user.private_ring.append(private_ring_row)

            QMessageBox.information(self, 'Generisanje ključa', 'Uspešno ste kreirali ključ')

            self.password_input.clear()
            self.radio_button_group.setExclusive(False)
            self.radio_button_1024.setChecked(False)
            self.radio_button_2048.setChecked(False)
            self.radio_button_group.setExclusive(True)

        elif not selected_button:
            QMessageBox.warning(self, 'Greška', 'Molimo vas da izaberete veličinu ključa.')
        elif not password:
            QMessageBox.warning(self, 'Greška', 'Molimo vas da unesete lozinku.')
