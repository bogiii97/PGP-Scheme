from PyQt5.QtCore import pyqtSignal, Qt
from PyQt5.QtWidgets import QWidget, QVBoxLayout, QLabel, QPushButton, QTableWidget, QTableWidgetItem, QRadioButton, QButtonGroup, QHBoxLayout

from application.util import convertPublicToPEM, convertPrivateToPEM


class SecondSendMessageWindow(QWidget):
    switch_to_menu = pyqtSignal(str)  # Signal za vraćanje na meni

    def __init__(self, user, users, selected_user_email, selected_algorithm, message):
        super().__init__()
        self.user = user
        self.users = users
        self.selected_user_email = selected_user_email
        self.selected_algorithm = selected_algorithm
        self.message = message

        self.sender_public_key_id = None
        self.sender_public_key = None
        self.sender_private_key = None

        self.receiver_public_key_id = None
        self.receiver_public_key = None

        self.setWindowTitle('Provera podataka')
        self.setFixedSize(600, 400)
        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout()

        self.back_button = QPushButton('Nazad na meni', self)
        self.back_button.clicked.connect(self.back_to_menu)
        layout.addWidget(self.back_button)

        # Kreiramo tabelu
        self.table = QTableWidget()
        self.table.setColumnCount(4)
        self.table.setHorizontalHeaderLabels(['Key ID', 'Public Key', 'Private Key', 'Select'])

        # Dodajemo redove u tabelu
        self.table.setRowCount(len(self.user.private_ring))
        self.button_group = QButtonGroup(self)
        self.button_group.setExclusive(True)  # Osiguravamo da samo jedan radio dugme može biti izabran

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
            radio_button.toggled.connect(lambda checked, id=key_pair.publicKey.keyID, pub=key_pair.publicKey.key, priv=key_pair.privateKey.key: self.radio_button_toggled(checked, id,pub,priv))
            self.button_group.addButton(radio_button)
            self.table.setCellWidget(row, 3, radio_button)

        layout.addWidget(self.table)

        self.receiverTable = QTableWidget()
        self.receiverTable.setColumnCount(3)
        self.receiverTable.setHorizontalHeaderLabels(['Key ID', 'Public Key', 'Select'])

        # Dodajemo redove u tabelu
        tmpList = [entry for entry in self.user.public_ring if entry.userID == self.selected_user_email]

        print(self.selected_user_email)
        for x in self.user.public_ring:
            print(x.userID)

        self.receiverTable.setRowCount(len(tmpList))
        self.button_group = QButtonGroup(self)
        self.button_group.setExclusive(True)  # Osiguravamo da samo jedan radio dugme može biti izabran

        for row, key_pair in enumerate(tmpList):
            public_key_pem = convertPublicToPEM(key_pair.publicKey.key)
            public_key_id = public_key_pem[-10:]

            public_key_item = QTableWidgetItem(public_key_pem)
            key_id_item = QTableWidgetItem(public_key_id)

            self.receiverTable.setItem(row, 0, key_id_item)
            self.receiverTable.setItem(row, 1, public_key_item)

            radio_button = QRadioButton()
            radio_button.toggled.connect(lambda checked, id=key_pair.publicKey.keyID, pub=key_pair.publicKey.key,: self.radio_button_toggled_receiver(checked, id, pub))
            self.button_group.addButton(radio_button)
            self.receiverTable.setCellWidget(row, 2, radio_button)

        layout.addWidget(self.receiverTable)


        # Dugme za slanje poruke
        self.send_button = QPushButton('Pošalji poruku', self)
        self.send_button.setFixedWidth(150)
        self.send_button.clicked.connect(self.send_message)
        layout.addWidget(self.send_button)

        self.setLayout(layout)

    def radio_button_toggled(self, checked, id, pub, priv):
        if checked:
            self.sender_public_key_id = id
            self.sender_public_key = pub
            self.sender_private_key = priv
            print(convertPublicToPEM(pub))
            print(convertPrivateToPEM(priv))

    def radio_button_toggled_receiver(self, checked, id, pub):
        if checked:
            self.receiver_public_key_id = id
            self.receiver_public_key = pub
            print(convertPublicToPEM(pub))

    def back_to_menu(self):
        self.switch_to_menu.emit(self.user.email)

    def send_message(self):
        pass
