from pymongo import MongoClient


class DBWrapper:
    def __init__(self, connection_string):
        self.client = MongoClient(connection_string)

    def get_connection(self, db_name, collection_name ):
        db = self.client[db_name]
        return db[collection_name]
    
    def find_one(self, db_name, collection_name, query):
        collection = self.get_connection(db_name, collection_name)
        return collection.find_one(query)
    
    def find(self, db_name, collection_name, query=None):
        collection = self.get_connection(db_name, collection_name)
        return collection.find(query)

    def insert_one(self, db_name, collection_name, data):
        collection = self.get_connection(db_name, collection_name)
        return collection.insert_one(data)
    
    def insert_many(self, db_name, collection_name, data):
        collection = self.get_connection(db_name, collection_name)
        return collection.insert_many(data)
    
    def update_one(self, db_name, collection_name, query, update):
        collection = self.get_connection(db_name, collection_name)
        return collection.update_one(query, update)
        
    def delete_one(self, db_name, collection_name, query):
        collection = self.get_connection(db_name, collection_name)
        return collection.delete_one(query)
    


wrapper = DBWrapper("mongodb://127.0.0.1:27017/")