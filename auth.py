from pymongo import MongoClient
from hashlib import sha256

# Connect to MongoDB Atlas
client = MongoClient("mongodb+srv://saiyeshwanth245:1234@cluster0.wflvo8t.mongodb.net/mongodb+srv://saiyeshwanth245:1234@cluster0.wflvo8t.mongodb.net/")
db = client["file_encryption_db"]
users = db["users"]

def hash_password(password):
    return sha256(password.encode()).hexdigest()

def create_user(username, password):
    if users.find_one({"username": username}):
        return False, "User already exists."
    users.insert_one({"username": username, "password": hash_password(password)})
    return True, "User created successfully."

def login_user(username, password):
    user = users.find_one({"username": username})
    if not user or user["password"] != hash_password(password):
        return False, "Invalid credentials."
    return True, "Login successful."
