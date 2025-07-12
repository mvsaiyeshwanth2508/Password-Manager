import os
from pymongo import MongoClient
from dotenv import load_dotenv

load_dotenv()

MONGO_URI = os.getenv("MONGO_URI")
client = MongoClient(MONGO_URI)
db = client["password_manager"]
users_collection = db["users"]

def get_user(username):
    return users_collection.find_one({"username": username})

def create_user(user_data):
    users_collection.insert_one(user_data)

def update_vault(username, vault):
    users_collection.update_one({"username": username}, {"$set": {"vault": vault}})
