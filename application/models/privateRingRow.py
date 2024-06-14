import os

class PrivateRingRow:
    def __init__(self, timeStamp, publicKey, privateKey, userID, ID = None):
        if ID is None:
            self.ID = self.setID()
        else:
            self.ID = ID
        self.timeStamp = timeStamp
        self.publicKey = publicKey
        self.privateKey = privateKey
        self.userID = userID

    def __repr__(self):
        pass


    def setID(self):
        file_path = os.path.join(os.path.dirname(__file__), '../../keyPairs/counter.txt')

        try:
            with open(file_path, 'r') as file:
                current_id = int(file.readline().strip())

            with open(file_path, 'w') as file:
                file.write(str(current_id + 1))

            return current_id
        except Exception as e:
            print(f"Error reading or writing to the file: {e}")
            return None
