import sys
from PyQt5.QtWidgets import QApplication, QStackedWidget, QDesktopWidget
from gui.login_window import LoginWindow
from gui.user_menu_window import UserMenuWindow
from gui.generate_keys_window import GenerateKeysWindow
from gui.private_ring_window import PrivateRingWindow  # Importujemo PrivateRingWindow
from models.user import User

class Controller:
    def __init__(self, users):
        self.widget = QStackedWidget()
        self.users = users

    def center_window(self, widget):
        screen = QDesktopWidget().screenGeometry()
        widget_geometry = widget.frameGeometry()
        center_point = screen.center()
        widget_geometry.moveCenter(center_point)
        widget.move(widget_geometry.topLeft())

    def show_login(self):
        self.login_window = LoginWindow(self.users)
        self.login_window.switch_window.connect(self.show_user_menu)
        self.widget.addWidget(self.login_window)
        self.widget.setCurrentWidget(self.login_window)
        self.widget.setFixedSize(200, 100)
        self.center_window(self.widget)

    def show_user_menu(self, email):
        user = self.find_user_by_email(email)
        if user is None:
            user = User(email.split("@")[0], email)
            self.users.append(user)


        self.user_menu_window = UserMenuWindow(user, self.users)
        self.user_menu_window.switch_window.connect(self.show_generate_keys)
        self.user_menu_window.switch_user.connect(self.show_login)
        self.user_menu_window.view_private_ring.connect(self.show_private_ring)  # Povezujemo signal sa metodom
        self.widget.addWidget(self.user_menu_window)
        self.widget.setCurrentWidget(self.user_menu_window)
        self.widget.setFixedSize(400, 250)
        self.center_window(self.widget)
    def show_generate_keys(self, user):
        self.generate_keys_window = GenerateKeysWindow(user)
        self.generate_keys_window.switch_to_menu.connect(self.show_user_menu)
        self.widget.addWidget(self.generate_keys_window)
        self.widget.setCurrentWidget(self.generate_keys_window)
        self.widget.setFixedSize(200, 300)
        self.center_window(self.widget)

    def show_private_ring(self, user, users):
        self.private_ring_window = PrivateRingWindow(user, users)
        self.private_ring_window.switch_to_menu.connect(self.show_user_menu)  # Povezujemo signal sa metodom
        self.widget.addWidget(self.private_ring_window)
        self.widget.setCurrentWidget(self.private_ring_window)
        self.widget.setFixedSize(1500, 400)
        self.center_window(self.widget)

    def find_user_by_email(self, email):
        for user in self.users:
            if user.email == email:
                return user
        return None

def main():
    users = []

    app = QApplication(sys.argv)
    controller = Controller(users)
    controller.show_login()
    controller.widget.show()
    sys.exit(app.exec_())

if __name__ == '__main__':
    main()
