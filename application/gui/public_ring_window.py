from PyQt5.QtWidgets import QWidget, QVBoxLayout, QLabel, QPushButton, QTableWidget, QTableWidgetItem, QHeaderView, QHBoxLayout
from PyQt5.QtCore import pyqtSignal, Qt
from application.util import *
import os

class PublicRingWindow(QWidget):
    switch_to_menu = pyqtSignal(object)  # Signal za vraćanje na meni

    def __init__(self, user, users):
        super().__init__()
        self.user = user
        self.users = users
        self.setWindowTitle('Javni prsten')
        self.setFixedSize(1500, 400)  # Postavljanje fiksne veličine prozora
        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout()

        self.back_button = QPushButton('Nazad na meni', self)
        self.back_button.clicked.connect(self.back_to_menu)
        layout.addWidget(self.back_button)

        self.table = QTableWidget()
        self.table.setColumnCount(5)
        self.table.setHorizontalHeaderLabels(['timeStamp', 'keyID', 'publicKey', 'userID', ''])
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        layout.addWidget(self.table)

        self.populate_table()

        self.setLayout(layout)

        # Centrirano dugme ispod tabele
        button_layout = QHBoxLayout()
        self.import_button = QPushButton('Uvezi javni', self)
        self.import_button.setFixedWidth(150)
        self.import_button.clicked.connect(self.import_public_key)
        button_layout.addStretch()
        button_layout.addWidget(self.import_button)
        button_layout.addStretch()
        layout.addLayout(button_layout)

    def populate_table(self):
        self.table.setRowCount(len(self.user.public_ring))
        for row, entry in enumerate(self.user.public_ring):
            self.table.setItem(row, 0, QTableWidgetItem(str(entry.timeStamp)))

            public_key_pem = convertPublicToPEM(entry.publicKey.key)
            public_key_id = public_key_pem[-10:]  # Najniža 64 bita kao string poslednjih 10 karaktera PEM formata
            self.table.setItem(row, 1, QTableWidgetItem(public_key_id))
            self.table.setItem(row, 2, QTableWidgetItem(public_key_pem))


            self.table.setItem(row, 3, QTableWidgetItem(entry.userID))

            delete_button = QPushButton('Izbrisi')
            self.table.setCellWidget(row, 4, delete_button)

            delete_button.clicked.connect(lambda _, pu=entry.publicKey.key: self.delete_key(pu))


    def back_to_menu(self):
        self.switch_to_menu.emit(self.user.email)

    def delete_key(self, public_key):
        id = -1
        for entry in self.user.public_ring:
            if entry.publicKey.key == public_key:
                id = entry.ID

        self.user.public_ring = [entry for entry in self.user.public_ring if entry.ID != id]

        #self.user.public_ring = [entry for entry in self.user.public_ring if entry.public_key.key != public_key]

        self.populate_table()

    def import_public_key(self):
        pass