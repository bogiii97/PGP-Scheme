import os
from PyQt5.QtCore import pyqtSignal
from PyQt5.QtWidgets import QWidget, QVBoxLayout, QLabel, QPushButton, QHBoxLayout

class ReceiveMessageWindow(QWidget):
    switch_to_menu = pyqtSignal(str)  # Signal za vraćanje na meni

    def __init__(self, user, users):
        super().__init__()
        self.user = user
        self.users = users
        self.message = ""

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
        # Implementacija funkcionalnosti za prijem poruke
        pass
