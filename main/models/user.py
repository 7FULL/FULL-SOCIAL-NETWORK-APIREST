class User:
    def __init__(self, username, password, email, phone, connector):
        self.username = username
        self.password = password
        self.email = email
        self.phone = phone
        self.status = 0
        self.connector = connector


    def __str__(self):
        return f"USER: {self.username}, {self.password}, {self.email}, {self.phone}, {self.status}"
    
    def toJson(self):
        return {
            "username": self.username,
            "password": self.password,
            "email": self.email,
            "phone": self.phone,
            "status": self.status,
            "emailVerified": False,
            "profile": "",
            "description": "",
            "token": ""
        }

    def register(self, keyStream):
        result = self.connector.client.FULL.users.insert_one({
            "username": self.username,
            "password": self.password,
            "email": self.email,
            "phone": self.phone,
            "status": self.status,
            "emailVerified": False,
            "profile": "",
            "description": "",
            "token": "",
            "streamkey": keyStream
        })
        return result
    
    @staticmethod
    def login(username, connector):
        result = connector.client.FULL.users.find_one({
            "username": username
        })

        if result == None:
            result = connector.client.FULL.users.find_one({
            "email": username
            })
        

        return result

