from PyQt5.QtWidgets import QWidget, QVBoxLayout, QPushButton, QLabel, QListWidget

class UserMenuWindow(QWidget):
    def __init__(self, email, users):
        super().__init__()
        self.setWindowTitle('User Menu')
        self.email = email
        self.users = users
        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout()

        self.email_label = QLabel(f'Logged in as: {self.email}', self)
        layout.addWidget(self.email_label)

        self.generate_key_button = QPushButton('Generisi kljuc', self)
        layout.addWidget(self.generate_key_button)

        self.view_rings_button = QPushButton('Pogledaj prstene', self)
        layout.addWidget(self.view_rings_button)

        self.import_key_button = QPushButton('Uvezi kljuc', self)
        layout.addWidget(self.import_key_button)

        self.export_key_button = QPushButton('Izvezi kljuc', self)
        layout.addWidget(self.export_key_button)

        self.send_message_button = QPushButton('Posalji poruku', self)
        layout.addWidget(self.send_message_button)

        self.receive_message_button = QPushButton('Primi poruku', self)
        layout.addWidget(self.receive_message_button)

        self.all_users_list = QListWidget(self)
        self.populate_all_users()
        layout.addWidget(self.all_users_list)

        self.setLayout(layout)

    def populate_all_users(self):
        for user in self.users:
            self.all_users_list.addItem(user.email)