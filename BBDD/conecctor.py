from pymongo.mongo_client import MongoClient

uri = "mongodb+srv://pi:678041577pP_p1h2g3pablo@cluster0.maizixh.mongodb.net/?retryWrites=true&w=majority"

class BBDD:
    def __init__(self):

        self.client = MongoClient(uri)

    def ping(self):    
        self.client.admin.command('ping')
        return "Pong"
        
