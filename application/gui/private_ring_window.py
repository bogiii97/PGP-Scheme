from datetime import datetime

from PyQt5.QtWidgets import QWidget, QVBoxLayout, QLabel, QPushButton, QTableWidget, QTableWidgetItem, QHeaderView, \
    QHBoxLayout, QFileDialog
from PyQt5.QtCore import pyqtSignal, Qt

from application.keys.private_key import PrivateKey
from application.keys.public_key import PublicKey
from application.models.privateRingRow import PrivateRingRow
from application.util import *
import os, re

class PrivateRingWindow(QWidget):
    switch_to_menu = pyqtSignal(object)  # Signal za vraćanje na meni

    def __init__(self, user, users):
        super().__init__()
        self.user = user
        self.users = users
        self.setWindowTitle('Privatni prsten')
        self.setFixedSize(1500, 400)  # Postavljanje fiksne veličine prozora
        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout()

        self.back_button = QPushButton('Nazad na meni', self)
        self.back_button.clicked.connect(self.back_to_menu)
        layout.addWidget(self.back_button)

        self.table = QTableWidget()
        self.table.setColumnCount(8)
        self.table.setHorizontalHeaderLabels(['timeStamp', 'keyID', 'publicKey', 'privateKey', 'userID', '', '', ''])
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        layout.addWidget(self.table)

        self.populate_table()

        self.setLayout(layout)

        # Centrirano dugme ispod tabele
        button_layout = QHBoxLayout()
        self.import_button = QPushButton('Uvezi par', self)
        self.import_button.setFixedWidth(150)
        self.import_button.clicked.connect(self.import_key_pair)
        button_layout.addStretch()
        button_layout.addWidget(self.import_button)
        button_layout.addStretch()
        layout.addLayout(button_layout)

    def back_to_menu(self):
        self.switch_to_menu.emit(self.user.email)

    def populate_table(self):
        self.table.setRowCount(len(self.user.private_ring))
        for row, entry in enumerate(self.user.private_ring):
            self.table.setItem(row, 0, QTableWidgetItem(str(entry.timeStamp)))

            public_key_pem = convertPublicToPEM(entry.publicKey.key)
            public_key_id = public_key_pem[-10:]  # Najniža 64 bita kao string poslednjih 10 karaktera PEM formata
            self.table.setItem(row, 1, QTableWidgetItem(public_key_id))
            self.table.setItem(row, 2, QTableWidgetItem(public_key_pem))

            private_key_pem = convertPrivateToPEM(entry.privateKey.key)
            self.table.setItem(row, 3, QTableWidgetItem(private_key_pem))

            self.table.setItem(row, 4, QTableWidgetItem(entry.userID))

            export_public_button = QPushButton('Izvezi javni')
            self.table.setCellWidget(row, 5, export_public_button)

            export_pair_button = QPushButton('Izvezi par')
            self.table.setCellWidget(row, 6, export_pair_button)

            delete_button = QPushButton('Izbrisi')
            self.table.setCellWidget(row, 7, delete_button)

            # Connecting button signals to methods
            export_public_button.clicked.connect(lambda _, pemPu=public_key_pem, pu=entry.publicKey.key: self.export_public_key(pemPu, pu))
            export_pair_button.clicked.connect(lambda _, pemPu=public_key_pem, pu=entry.publicKey.key, pemPr=private_key_pem: self.export_key_pair(pemPu, pu, pemPr))
            delete_button.clicked.connect(lambda _, pu=entry.publicKey.key: self.delete_key(pu))

    def export_public_key(self, public_key_pem, public_key):
        # Implement your export public key logic here
        print(f'Public key PEM: {public_key_pem}')

        print("Javni ključ prilikom izvoza")
        print(public_key[-8:])

        keysPairsRelativePath = "..\\keyPairs"
        userFolderExists = self.does_user_folder_exists(keysPairsRelativePath, self.user.email)
        if not userFolderExists:
            self.create_user_folder(keysPairsRelativePath, self.user.email)

        filename = ""
        for entry in self.user.private_ring:
            if entry.publicKey.key == public_key:
                filename = str(entry.ID) + ".txt"
        file_data = public_key_pem


        file_path = os.path.join(keysPairsRelativePath, self.user.email, "public", filename)
        with open(file_path, 'w') as file:
            file.write(file_data)
        print(f'File {filename} created at {file_path}')

    def export_key_pair(self, public_key_pem, public_key, private_key_pem):
        print(f'Public key PEM: {public_key_pem}')
        print(f'Private key PEM: {private_key_pem}')

        keysPairsRelativePath = "..\\keyPairs"
        userFolderExists = self.does_user_folder_exists(keysPairsRelativePath, self.user.email)
        if not userFolderExists:
            self.create_user_folder(keysPairsRelativePath, self.user.email)

        filename = ""
        for entry in self.user.private_ring:
            if entry.publicKey.key == public_key:
                filename = str(entry.ID) + ".txt"
        file_data = public_key_pem + "\n\n+++++++++++++++++++\n\n" + private_key_pem

        file_path = os.path.join(keysPairsRelativePath, self.user.email, "pair", filename)
        with open(file_path, 'w') as file:
            file.write(file_data)
        print(f'File {filename} created at {file_path}')

    def delete_key(self, public_key):
        id = -1
        for entry in self.user.private_ring:
            if entry.publicKey.key == public_key:
                id = entry.ID

        self.user.private_ring = [entry for entry in self.user.private_ring if entry.ID != id]
        for user in self.users:
            user.public_ring = [entry for entry in user.public_ring if entry.ID != id]
            for x in user.public_ring:
                print(user.email, x.ID)
        keysPairsRelativePath = "..\\keyPairs"
        public_file_path = os.path.join(keysPairsRelativePath, self.user.email, "public", f"{id}.txt")
        pair_file_path = os.path.join(keysPairsRelativePath, self.user.email, "pair", f"{id}.txt")

        if os.path.exists(public_file_path):
            os.remove(public_file_path)
            print(f'File {public_file_path} deleted')

        if os.path.exists(pair_file_path):
            os.remove(pair_file_path)
            print(f'File {pair_file_path} deleted')

        self.populate_table()

    def import_key_pair(self):
        # Putanja do korisničkog foldera sa folderom 'pair'
        user_folder_path = os.path.join("..\\keyPairs", self.user.email, "pair")

        # Otvaranje dijaloga za odabir fajla
        options = QFileDialog.Options()
        file_name, _ = QFileDialog.getOpenFileName(self, "Odaberite fajl sa parom ključeva", user_folder_path,
                                                   "Text Files (*.txt);;All Files (*)", options=options)
        if file_name:
            try:
                # Čitanje sadržaja fajla
                with open(file_name, 'r') as file:
                    file_content = file.read()
                    print(f'Sadržaj fajla {file_name}:')


                    match = re.search(r'/(\d+)\.txt$', file_name)
                    if match: userId = match.group(1)
                    else: print("Broj nije pronađen na putanji")
                    print(userId)

                    #ovde imas file_content
                    public_pem_cleaned, private_pem_cleaned = file_content.split("+++++++++++++++++++")
                    public_pem_cleaned = public_pem_cleaned.strip()
                    private_pem_cleaned = private_pem_cleaned.strip()

                    public_byte = convertPEMToPublic(public_pem_cleaned)
                    encrypyed_private_byte = convertPEMToPrivate(private_pem_cleaned)

                    lowest_64_bits_bytes = public_byte[-8:]

                    private_key = PrivateKey(encrypyed_private_byte)
                    public_key = PublicKey(public_byte, lowest_64_bits_bytes)
                    private_ring_row = PrivateRingRow(datetime.now(), public_key, private_key, self.user.email, int(userId))
                    print(userId)
                    self.user.private_ring.append(private_ring_row)
            except Exception as e:
                print(f"Greška prilikom čitanja fajla: {e}")
        self.populate_table()

    def does_user_folder_exists(self, path, email):
        folder_path = os.path.join(path, email)
        return os.path.isdir(folder_path)

    def create_user_folder(self, path, email):
        folder_path = os.path.join(path, email)
        os.makedirs(os.path.join(folder_path, 'public'), exist_ok=True)
        os.makedirs(os.path.join(folder_path, 'pair'), exist_ok=True)
