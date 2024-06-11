from PyQt5.QtWidgets import QWidget, QVBoxLayout, QPushButton, QLabel, QListWidget
from PyQt5.QtCore import pyqtSignal

class UserMenuWindow(QWidget):
    switch_window = pyqtSignal(object)

    def __init__(self, user):
        super().__init__()
        self.setWindowTitle('User Menu')
        self.user = user
        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout()

        self.email_label = QLabel(f'Logged in as: {self.user.email}', self)
        layout.addWidget(self.email_label)

        self.generate_key_button = QPushButton('Generisi kljuc', self)
        self.generate_key_button.clicked.connect(self.show_generate_keys_window)
        layout.addWidget(self.generate_key_button)

        self.view_private_ring_button = QPushButton('Pogledaj privatni prsten', self)
        layout.addWidget(self.view_private_ring_button)

        self.view_public_ring_button = QPushButton('Pogledaj javni prsten', self)
        layout.addWidget(self.view_public_ring_button)

        self.import_key_button = QPushButton('Uvezi kljuc', self)
        layout.addWidget(self.import_key_button)

        self.export_key_button = QPushButton('Izvezi kljuc', self)
        layout.addWidget(self.export_key_button)

        self.send_message_button = QPushButton('Posalji poruku', self)
        layout.addWidget(self.send_message_button)

        self.receive_message_button = QPushButton('Primi poruku', self)
        layout.addWidget(self.receive_message_button)

        self.setLayout(layout)

    def show_generate_keys_window(self):
        self.switch_window.emit(self.user)
