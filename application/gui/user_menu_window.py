from PyQt5.QtWidgets import QWidget, QVBoxLayout, QPushButton, QLabel
from PyQt5.QtCore import pyqtSignal

class UserMenuWindow(QWidget):
    switch_window = pyqtSignal(object)
    switch_user = pyqtSignal()
    view_private_ring = pyqtSignal(object, list)  # Dodajemo novi signal
    view_public_ring = pyqtSignal(object, list)  # Dodajemo novi signal za javni prsten

    def __init__(self, user, users):
        super().__init__()
        self.setWindowTitle('Korisnički meni')
        self.user = user
        self.users = users
        self.setFixedSize(400, 250)
        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout()

        self.email_label = QLabel(f'Korisnik: {self.user.email}', self)
        layout.addWidget(self.email_label)

        self.generate_key_button = QPushButton('Generisi kljuc', self)
        self.generate_key_button.clicked.connect(self.show_generate_keys_window)
        layout.addWidget(self.generate_key_button)

        self.view_private_ring_button = QPushButton('Pogledaj privatni prsten', self)
        self.view_private_ring_button.clicked.connect(self.show_private_ring_window)  # Povezujemo dugme sa metodom
        layout.addWidget(self.view_private_ring_button)

        self.view_public_ring_button = QPushButton('Pogledaj javni prsten', self)
        self.view_public_ring_button.clicked.connect(self.show_public_ring_window)  # Povezujemo dugme sa metodom
        layout.addWidget(self.view_public_ring_button)

        self.send_message_button = QPushButton('Posalji poruku', self)
        layout.addWidget(self.send_message_button)

        self.receive_message_button = QPushButton('Primi poruku', self)
        layout.addWidget(self.receive_message_button)

        self.switch_user_button = QPushButton('Promeni korisnika', self)
        self.switch_user_button.clicked.connect(self.switch_user.emit)
        layout.addWidget(self.switch_user_button)

        self.setLayout(layout)

    def show_generate_keys_window(self):
        self.switch_window.emit(self.user)

    def show_private_ring_window(self):
        self.view_private_ring.emit(self.user, self.users)  # Emitujemo signal sa korisnikom i listom korisnika

    def show_public_ring_window(self):
        self.view_public_ring.emit(self.user, self.users)  # Emitujemo signal sa korisnikom i listom korisnika
