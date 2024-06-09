import os

class PrivateRing:
    def __init__(self, passphrasePassword, timeStamp, keyID, publicKey, privateKey, userID):
        self.ID = self.setID()
        self.passphrasePassword = passphrasePassword
        self.timeStamp = timeStamp
        self.keyID = keyID
        self.publicKey = publicKey
        self.privateKey = privateKey
        self.userID = userID

    def __repr__(self):
        return (f"PrivateRing:\nID={self.ID}\npassphrasePassword={self.passphrasePassword}\ntimeStamp={self.timeStamp}\n"
                f"keyID={self.keyID}\npublicKey={self.publicKey}\nprivateKey={self.privateKey}\nuserID={self.userID}")


    def setID(self):
        file_path = os.path.join(os.path.dirname(__file__), '../../ParoviKljučeva/Brojač.txt')

        try:
            with open(file_path, 'r') as file:
                current_id = int(file.readline().strip())

            with open(file_path, 'w') as file:
                file.write(str(current_id + 1))

            return current_id
        except Exception as e:
            print(f"Error reading or writing to the file: {e}")
            return None
