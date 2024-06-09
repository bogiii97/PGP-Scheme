class PublicRing:
    def __init__(self, ID, timeStamp, keyID, publicKey,userID):
        self.ID = ID
        self.timeStamp = timeStamp
        self.keyID = keyID
        self.publicKey = publicKey
        self.userID = userID

    def __repr__(self):
        return (f"PrivateRing:\nID={self.ID}\ntimeStamp={self.timeStamp}\n"
            f"keyID={self.keyID}\npublicKey={self.publicKey}\nuserID={self.userID}")
