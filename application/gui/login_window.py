from PyQt5.QtWidgets import QWidget, QVBoxLayout, QLineEdit, QPushButton, QMessageBox
from PyQt5.QtCore import pyqtSignal

class LoginWindow(QWidget):
    switch_window = pyqtSignal(str)

    def __init__(self, users):
        super().__init__()
        self.users = users
        self.setWindowTitle('Prijava')
        self.init_ui()
        self.setFixedSize(200, 100)

    def init_ui(self):
        layout = QVBoxLayout()

        self.email_input = QLineEdit(self)
        self.email_input.setPlaceholderText('Enter your email')
        layout.addWidget(self.email_input)

        self.submit_button = QPushButton('Uloguj se', self)
        self.submit_button.clicked.connect(self.submit_email)
        layout.addWidget(self.submit_button)

        self.setLayout(layout)

    def submit_email(self):
        email = self.email_input.text()
        if not email:
            QMessageBox.warning(self, 'Input Error', 'Please enter your email.')
            return

        self.switch_window.emit(email)
        self.close()
