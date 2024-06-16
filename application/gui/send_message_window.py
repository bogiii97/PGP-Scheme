import os
from PyQt5.QtCore import pyqtSignal
from PyQt5.QtWidgets import QWidget, QVBoxLayout, QLabel, QPushButton, QComboBox, QLineEdit, QCheckBox, QMessageBox

class SendMessageWindow(QWidget):
    switch_to_menu = pyqtSignal(str)  # Signal za vraćanje na meni
    proceed_signal = pyqtSignal(object, list, str, str, list)  # Signal za Dalje dugme

    key_pairs_path = "..\\keyPairs"  # Dodajemo promenljivu za putanju

    def __init__(self, user, users):
        super().__init__()
        self.user = user
        self.users = users
        self.selected_user_email = None
        self.message = ""
        self.selected_options = []

        self.setWindowTitle('Slanje poruke')
        self.setFixedSize(500, 500)  # Povećan prozor
        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout()

        self.back_button = QPushButton('Nazad na meni', self)
        self.back_button.clicked.connect(self.back_to_menu)
        layout.addWidget(self.back_button)

        # Dropdown za izbor korisnika
        self.user_dropdown = QComboBox(self)
        self.populate_user_dropdown()
        self.user_dropdown.currentIndexChanged.connect(self.select_user_email)
        layout.addWidget(QLabel('Izaberite korisnika:'))
        layout.addWidget(self.user_dropdown)

        layout.addWidget(QLabel('Izaberite opcije:'))
        self.auth_checkbox = QCheckBox('Autentikacija')
        self.compression_checkbox = QCheckBox('Kompresija')
        self.secrecy_checkbox = QCheckBox('Tajnost')
        self.radix64_checkbox = QCheckBox('Radix 64')
        layout.addWidget(self.auth_checkbox)
        layout.addWidget(self.compression_checkbox)
        layout.addWidget(self.secrecy_checkbox)

        layout.addWidget(self.radix64_checkbox)

        # Input za poruku
        self.message_input = QLineEdit(self)
        self.message_input.textChanged.connect(self.update_message)
        layout.addWidget(QLabel('Unesite poruku:'))
        layout.addWidget(self.message_input)

        # Dugme Dalje
        self.proceed_button = QPushButton('Dalje', self)
        self.proceed_button.clicked.connect(self.proceed)
        layout.addWidget(self.proceed_button)

        self.setLayout(layout)

        # Postavi prvi korisnik kao podrazumevani ako postoji
        if self.user_dropdown.count() > 0:
            self.selected_user_email = self.user_dropdown.itemText(0)

    def back_to_menu(self):
        self.switch_to_menu.emit(self.user.email)

    def populate_user_dropdown(self):
        try:
            for item in os.listdir(self.key_pairs_path):
                item_path = os.path.join(self.key_pairs_path, item)
                if os.path.isdir(item_path) and item != "counter.txt":
                    if item != self.user.email:
                        self.user_dropdown.addItem(item)
            # Postavi prvi korisnik kao podrazumevani ako postoji
            if self.user_dropdown.count() > 0:
                self.selected_user_email = self.user_dropdown.itemText(0)
        except Exception as e:
            print(f"Greška prilikom čitanja foldera: {e}")

    def select_user_email(self, index):
        self.selected_user_email = self.user_dropdown.itemText(index)

    def update_message(self, text):
        self.message = text

    def proceed(self):
        self.selected_options = []
        if self.secrecy_checkbox.isChecked():
            self.selected_options.append('Tajnost')
        if self.auth_checkbox.isChecked():
            self.selected_options.append('Autentikacija')
        if self.compression_checkbox.isChecked():
            self.selected_options.append('Kompresija')
        if self.radix64_checkbox.isChecked():
            self.selected_options.append('Radix 64')

        if not self.selected_user_email:
            QMessageBox.warning(self, 'Upozorenje', 'Morate izabrati korisnika')
        elif not self.selected_options:
            QMessageBox.warning(self, 'Upozorenje', 'Morate izabrati bar jednu opciju')
        elif not self.message:
            QMessageBox.warning(self, 'Upozorenje', 'Morate uneti poruku')
        else:
            self.proceed_signal.emit(self.user, self.users, self.selected_user_email, self.message, self.selected_options)
