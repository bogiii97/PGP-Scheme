import secrets

from PyQt5.QtCore import pyqtSignal, Qt
from PyQt5.QtWidgets import QWidget, QVBoxLayout, QLabel, QPushButton, QTableWidget, QTableWidgetItem, QRadioButton, \
    QButtonGroup, QLineEdit, QMessageBox
import hashlib
import time
import zlib
import base64, os

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.serialization import load_pem_public_key, load_der_public_key

from application.util import convertPublicToPEM, convertPrivateToPEM

class SecondSendMessageWindow(QWidget):
    switch_to_menu = pyqtSignal(str)  # Signal za vraćanje na meni

    def __init__(self, user, users, selected_user_email, message, selected_options):
        super().__init__()
        self.user = user
        self.users = users
        self.selected_user_email = selected_user_email
        self.message = message
        self.selected_options = selected_options

        self.selected_algorithm = None

        self.sender_public_key_id = None
        self.sender_public_key = None
        self.sender_private_key = None

        self.receiver_public_key_id = None
        self.receiver_public_key = None

        self.setWindowTitle('Provera podataka')
        self.setFixedSize(600, 550)
        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout()

        self.back_button = QPushButton('Nazad na meni', self)
        self.back_button.clicked.connect(self.back_to_menu)
        layout.addWidget(self.back_button)

        if 'Autentikacija' in self.selected_options:
            self.table = QTableWidget()
            self.table.setColumnCount(4)
            self.table.setHorizontalHeaderLabels(['Key ID', 'Public Key', 'Private Key', 'Select'])

            self.table.setRowCount(len(self.user.private_ring))
            self.sender_button_group = QButtonGroup(self)
            self.sender_button_group.setExclusive(True)  # Osiguravamo da samo jedan radio dugme može biti izabran

            for row, key_pair in enumerate(self.user.private_ring):
                public_key_pem = convertPublicToPEM(key_pair.publicKey.key)
                public_key_id = public_key_pem[-10:]
                private_key_pem = convertPrivateToPEM(key_pair.privateKey.key)

                public_key_item = QTableWidgetItem(public_key_pem)
                key_id_item = QTableWidgetItem(public_key_id)
                private_key_item = QTableWidgetItem(private_key_pem)

                self.table.setItem(row, 0, key_id_item)
                self.table.setItem(row, 1, public_key_item)
                self.table.setItem(row, 2, private_key_item)

                radio_button = QRadioButton()
                radio_button.toggled.connect(lambda checked, id=key_pair.publicKey.keyID, pub=key_pair.publicKey.key, priv=key_pair.privateKey.key: self.radio_button_toggled(checked, id, pub, priv))
                self.sender_button_group.addButton(radio_button)
                self.table.setCellWidget(row, 3, radio_button)

            layout.addWidget(self.table)

            self.password_input = QLineEdit(self)
            self.password_input.setPlaceholderText('Unesite lozinku')
            self.password_input.setEchoMode(QLineEdit.Password)
            layout.addWidget(self.password_input)

        if 'Tajnost' in self.selected_options:
            self.receiver_table = QTableWidget()
            self.receiver_table.setColumnCount(3)
            self.receiver_table.setHorizontalHeaderLabels(['Key ID', 'Public Key', 'Select'])

            tmp_list = [entry for entry in self.user.public_ring if entry.userID == self.selected_user_email]
            self.receiver_table.setRowCount(len(tmp_list))
            self.receiver_button_group = QButtonGroup(self)
            self.receiver_button_group.setExclusive(True)  # Osiguravamo da samo jedan radio dugme može biti izabran

            for row, key_pair in enumerate(tmp_list):
                public_key_pem = convertPublicToPEM(key_pair.publicKey.key)
                public_key_id = public_key_pem[-10:]

                public_key_item = QTableWidgetItem(public_key_pem)
                key_id_item = QTableWidgetItem(public_key_id)

                self.receiver_table.setItem(row, 0, key_id_item)
                self.receiver_table.setItem(row, 1, public_key_item)

                radio_button = QRadioButton()
                radio_button.toggled.connect(lambda checked, id=key_pair.publicKey.keyID, pub=key_pair.publicKey.key: self.radio_button_toggled_receiver(checked, id, pub))
                self.receiver_button_group.addButton(radio_button)
                self.receiver_table.setCellWidget(row, 2, radio_button)

            layout.addWidget(self.receiver_table)

            self.alg1_radio = QRadioButton('Triple DES')
            self.alg2_radio = QRadioButton('AES-128')
            self.alg_group = QButtonGroup(self)
            self.alg_group.addButton(self.alg1_radio)
            self.alg_group.addButton(self.alg2_radio)
            self.alg_group.buttonClicked.connect(self.select_algorithm)
            layout.addWidget(QLabel('Izaberite algoritam:'))
            layout.addWidget(self.alg1_radio)
            layout.addWidget(self.alg2_radio)

        if 'Autentikacija' in self.selected_options or 'Tajnost' in self.selected_options:
            self.send_button = QPushButton('Pošalji poruku', self)
            self.send_button.setFixedWidth(150)
            self.send_button.clicked.connect(self.send_message)
            layout.addWidget(self.send_button)
        else:
            self.send_message()


        self.setLayout(layout)

    def radio_button_toggled(self, checked, id, pub, priv):
        if checked:
            self.sender_public_key_id = id
            self.sender_public_key = pub
            self.sender_private_key = priv

    def radio_button_toggled_receiver(self, checked, id, pub):
        if checked:
            self.receiver_public_key_id = id
            self.receiver_public_key = pub

    def back_to_menu(self):
        self.switch_to_menu.emit(self.user.email)

    def select_algorithm(self, button):
        self.selected_algorithm = button.text()

    def send_message(self):
        if 'Autentikacija' in self.selected_options:
            if not self.password_input.text() or not self.sender_public_key_id:
                QMessageBox.warning(self, 'Upozorenje', 'Morate izabrati sve parametre za autentikaciju')
                return

        if 'Tajnost' in self.selected_options:
            if not self.selected_algorithm or not self.receiver_public_key_id:
                QMessageBox.warning(self, 'Upozorenje', 'Morate izabrati sve parametre za tajnost')
                return

        # Prepare the message with filename and timestamp
        timestamp = str(int(time.time()))
        filename = "message.txt"
        M = f"{self.message}\n{timestamp}\n{filename}"

        if 'Autentikacija' in self.selected_options:
            try:
                password = self.password_input.text()
                sha1 = hashlib.sha1()
                sha1.update(password.encode('utf-8'))
                hashed_password = sha1.digest()

                # Decrypt the private key using CAST-128
                key = hashed_password[:16]  # CAST-128 uses a 128-bit key
                iv = hashed_password[:8]
                cipher = Cipher(algorithms.CAST5(key), modes.CFB(iv), backend=default_backend())
                decryptor = cipher.decryptor()
                decrypted_private_key_bytes = decryptor.update(self.sender_private_key) + decryptor.finalize()

                private_key = serialization.load_der_private_key(
                    decrypted_private_key_bytes,
                    password=None,
                    backend=default_backend()
                )

                # Sign the message
                message_hash = hashlib.sha1(M.encode('utf-8')).digest()
                signature = private_key.sign(
                    message_hash,
                    padding.PKCS1v15(),
                    hashes.SHA1()
                )
            except Exception as e:
                print(e)
            # Append the timestamp, sender's public key ID, and signature to the message
            M += f"\n{timestamp}\n{self.sender_public_key_id}\n{signature.hex()}"

        if 'Kompresija' in self.selected_options:
            M = zlib.compress(M.encode('utf-8'))

        flag_map = {
            "Autentikacija": "0",
            "Kompresija": "1",
            "Tajnost": "2",
            "Radix 64": "3"
        }

        # Generate the flag string
        flags = [flag_map[option] for option in self.selected_options]
        flag_string = ','.join(flags)

        # Write the message to a file
        message_dir = f"..\\keyPairs\\{self.selected_user_email}\\inbox"
        os.makedirs(message_dir, exist_ok=True)  # Ensure the directory exists
        message_path = os.path.join(message_dir, "message.txt")

        with open(message_path, 'w') as f:
            f.write(f"{flag_string}\n{M}")

        QMessageBox.information(self, 'Poruka poslana', 'Poruka je uspešno poslata i sačuvana.')
        self.back_to_menu()

        """
              if 'Autentikacija' in self.selected_options:
                  password = self.password_input.text()
                  print(password)
                  sha1 = hashlib.sha1()
                  sha1.update(password.encode('utf-8'))
                  hashed_password = sha1.digest()

                  # Extract the key and IV
                  key = hashed_password[:16]  # CAST-128 uses a 128-bit key
                  iv = self.sender_private_key[:8]  # Extract the first 8 bytes as IV
                  encrypted_data = self.sender_private_key[8:]  # The rest is the encrypted private key
                  print(convertPrivateToPEM(self.sender_private_key))
                  # Decrypt the private key using CAST-128
                  cipher = Cipher(algorithms.CAST5(key), modes.CFB(iv), backend=default_backend())
                  decryptor = cipher.decryptor()
                  private_byte = decryptor.update(encrypted_data) + decryptor.finalize()

                  # Load the private key
                  try:
                      private_key = serialization.load_der_private_key(
                          private_byte,
                          password=None,
                          backend=default_backend()
                      )
                      print("Private key successfully loaded.")
                  except Exception as e:
                      print(f"Failed to load private key: {e}")

                  # Create the message digest and sign it
                  md = hashlib.sha1(M.encode('utf-8')).digest()
                  signature = private_key.sign(md, padding.PKCS1v15(), hashes.SHA1())

                  # Prepare the signature structure
                  signature_structure = f"{timestamp}\n{self.sender_public_key_id}\n{signature.hex()}"
                  M = f"{M}\n{signature_structure}"


              # Compress the message if selected
              if 'Kompresija' in self.selected_options:
                  M = zlib.compress(M.encode('utf-8'))

              # Encrypt the message if selected
              if 'Tajnost' in self.selected_options:
                  # Generate a session key
                  if self.selected_algorithm == 'Triple DES':
                      session_key = secrets.token_bytes(24)  # Triple DES uses a 24-byte key
                      cipher_algorithm = algorithms.TripleDES(session_key)
                      iv = secrets.token_bytes(8)  # Triple DES uses an 8-byte IV
                  elif self.selected_algorithm == 'AES-128':
                      session_key = secrets.token_bytes(16)  # AES-128 uses a 16-byte key
                      cipher_algorithm = algorithms.AES(session_key)
                      iv = secrets.token_bytes(16)  # AES uses a 16-byte IV
                  else:
                      raise ValueError("Unsupported algorithm selected")


                  # Encrypt the message with the session key
                  try:
                      cipher = Cipher(cipher_algorithm, modes.CFB(iv), backend=default_backend())
                      encryptor = cipher.encryptor()
                      encrypted_message = encryptor.update(M) + encryptor.finalize()
                  except Exception as e:
                      print(f"Encryption error: {e}")
                      return

                  # Encrypt the session key with the receiver's public key
                  try:
                      self.receiver_public_key = load_der_public_key(
                          self.receiver_public_key,
                          backend=default_backend()
                      )
                      encrypted_session_key = self.receiver_public_key.encrypt(
                          session_key,
                          padding.OAEP(
                              mgf=padding.MGF1(algorithm=hashes.SHA1()),
                              algorithm=hashes.SHA1(),
                              label=None
                          )
                      )
                  except Exception as e:
                      print(e)
                  if encrypted_session_key is not None:
                      M = f"{self.receiver_public_key_id}\n{encrypted_session_key}\n{iv}\n{encrypted_message}"
                      print("Final message structure prepared.")
                  else:
                      print("Failed to encrypt session key.")
                      return

              # Encode the message in Radix64 format if selected
              if 'Radix 64' in self.selected_options:
                  M = base64.b64encode(M).decode('utf-8')
              """