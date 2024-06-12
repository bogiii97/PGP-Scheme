from PyQt5.QtWidgets import QWidget, QVBoxLayout, QLabel, QPushButton, QTableWidget, QTableWidgetItem, QHeaderView, QHBoxLayout
from PyQt5.QtCore import pyqtSignal, Qt
from application.util import *
import os

class PrivateRingWindow(QWidget):
    switch_to_menu = pyqtSignal(object)  # Signal za vraćanje na meni

    def __init__(self, user, users):
        super().__init__()
        self.user = user
        self.users = users
        self.setWindowTitle('Private Ring')
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
        self.import_button = QPushButton('Import Pair', self)
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
            delete_button.clicked.connect(lambda _, r=row: self.delete_key(r))

    def export_public_key(self, public_key_pem, public_key):
        # Implement your export public key logic here
        print(f'Public key PEM: {public_key_pem}')

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

    def delete_key(self, row):
        # Implement your delete key logic here
        print(f'Delete key for row {row}')

    def import_key_pair(self):
        # Implement your import key pair logic here
        print('Import key pair')

    def does_user_folder_exists(self, path, email):
        folder_path = os.path.join(path, email)
        return os.path.isdir(folder_path)

    def create_user_folder(self, path, email):
        folder_path = os.path.join(path, email)
        os.makedirs(os.path.join(folder_path, 'public'), exist_ok=True)
        os.makedirs(os.path.join(folder_path, 'pair'), exist_ok=True)
