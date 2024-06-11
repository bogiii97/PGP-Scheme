import sys
from PyQt5.QtWidgets import QApplication
from PyQt5.QtWidgets import QStackedWidget
from gui.login_window import LoginWindow
from gui.user_menu_window import UserMenuWindow


from models.user import User

class Controller:
    def __init__(self, users):
        self.widget = QStackedWidget()
        self.users = users

    def show_login(self):
        self.login_window = LoginWindow(self.users)
        self.login_window.switch_window.connect(self.show_user_menu)
        self.widget.addWidget(self.login_window)
        self.widget.setCurrentWidget(self.login_window)

    def show_user_menu(self, email):

        user = self.find_user_by_email(email)
        if user:
            self.user_menu_window = UserMenuWindow(email, self.users)
            self.widget.addWidget(self.user_menu_window)
            self.widget.setCurrentWidget(self.user_menu_window)
        else:
            pass



    def find_user_by_email(self, email):
        for user in self.users:
            if user.email == email:
                return user
        return None

def main():

    users = []

    userA = User("a", "a@gmail.com")
    userB = User("b", "b@gmail.com")
    userC = User("c", "c@gmail.com")

    users.append(userA)
    users.append(userB)
    users.append(userC)

    app = QApplication(sys.argv)
    controller = Controller(users)
    controller.show_login()
    controller.widget.show()
    sys.exit(app.exec_())

if __name__ == '__main__':
    main()