import os
from PyQt5.QtCore import pyqtSignal
from PyQt5.QtWidgets import QWidget, QVBoxLayout, QLabel, QPushButton, QComboBox, QRadioButton, QLineEdit, QButtonGroup

class SendMessageWindow(QWidget):
    switch_to_menu = pyqtSignal(str)  # Signal za vraćanje na meni
    proceed_signal = pyqtSignal(object, list, str, str, str)  # Signal za Dalje dugme

    key_pairs_path = "..\\keyPairs"  # Dodajemo promenljivu za putanju

    def __init__(self, user, users):
        super().__init__()
        self.user = user
        self.users = users
        self.selected_user_email = None
        self.selected_algorithm = None
        self.message = ""

        self.setWindowTitle('Slanje poruke')
        self.setFixedSize(500, 400)  # Povećan prozor
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

        # Radio dugmad za algoritme
        self.alg1_radio = QRadioButton('alg1')
        self.alg2_radio = QRadioButton('alg2')
        self.alg_group = QButtonGroup(self)
        self.alg_group.addButton(self.alg1_radio)
        self.alg_group.addButton(self.alg2_radio)
        self.alg_group.buttonClicked.connect(self.select_algorithm)
        layout.addWidget(QLabel('Izaberite algoritam:'))
        layout.addWidget(self.alg1_radio)
        layout.addWidget(self.alg2_radio)

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

    def back_to_menu(self):
        self.switch_to_menu.emit(self.user.email)

    def populate_user_dropdown(self):
        try:
            for item in os.listdir(self.key_pairs_path):
                item_path = os.path.join(self.key_pairs_path, item)
                if os.path.isdir(item_path) and item != "counter.txt":
                    if item != self.user.email:
                        self.user_dropdown.addItem(item)
        except Exception as e:
            print(f"Greška prilikom čitanja foldera: {e}")

    def select_user_email(self, index):
        self.selected_user_email = self.user_dropdown.itemText(index)

    def select_algorithm(self, button):
        self.selected_algorithm = button.text()

    def update_message(self, text):
        self.message = text

    def proceed(self):
        self.proceed_signal.emit(self.user, self.users, self.selected_user_email, self.selected_algorithm, self.message)
