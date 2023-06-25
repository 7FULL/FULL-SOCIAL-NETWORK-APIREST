class User:
    def __init__(self, username, password, email, phone, admin, status, connector):
        self.username = username
        self.password = password
        self.email = email
        self.phone = phone
        self.admin = admin
        self.status = status
        self.connector = connector


    def __str__(self):
        return f"USER: {self.username}, {self.password}, {self.email}, {self.phone}, {self.admin}, {self.status}"
    

    def register(self):
        result = self.connector.client.FULL.users.insert_one({
            "username": self.username,
            "password": self.password,
            "email": self.email,
            "phone": self.phone,
            "admin": self.admin,
            "status": self.status
        })
        return result
    
    @staticmethod
    def login(username, password, connector):
        result = connector.client.FULL.users.find_one({
            "username": username,
            "password": password
        })
        return result

