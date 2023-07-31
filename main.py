from fastapi import FastAPI, HTTPException, Depends, status, Response, Cookie, Request
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from pydantic import BaseModel
from pymongo import MongoClient
from passlib.context import CryptContext

app = FastAPI(debug=True)

# MongoDB configuration
MONGODB_CONNECTION_STRING = "mongodb+srv://arshisiddiqui1994:siddiqui1994@cluster0.uzhypxk.mongodb.net/"
MONGODB_DB_NAME = "Cluster1"
MONGODB_COLLECTION_NAME = "users"

client = MongoClient(MONGODB_CONNECTION_STRING)
db = client[MONGODB_DB_NAME]
collection = db[MONGODB_COLLECTION_NAME]

# Password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Security
security = HTTPBasic()

# Model for user registration
class UserRegistration(BaseModel):
    username: str
    password: str

# Model for user login
class UserLogin(BaseModel):
    username: str
    password: str

# Helper function to create a new user in the database
def create_user(username: str, password: str):
    hashed_password = pwd_context.hash(password)
    collection.insert_one({"username": username, "password": hashed_password})

# Helper function to check if the user exists in the database
def find_user(username: str):
    return collection.find_one({"username": username})

@app.post("/register", status_code=status.HTTP_201_CREATED)
def register(user: UserRegistration):
    user_db = find_user(user.username)
    if user_db:
        raise HTTPException(status_code=400, detail="User already exists")
    create_user(user.username, user.password)
    return {"message": "User registered successfully"}

@app.post("/login")
def login(user: UserLogin, response: Response, request: Request):
    user_db = find_user(user.username)
    if user_db and pwd_context.verify(user.password, user_db['password']):
        response.set_cookie(key="session", value="logged_in_user")
        return {"message": "Login successful"}
    raise HTTPException(status_code=401, detail="Invalid credentials")

@app.get("/secure_endpoint")
def secure_endpoint(credentials: HTTPBasicCredentials = Depends(security)):
    user = find_user(credentials.username)
    if user and pwd_context.verify(credentials.password, user['password']):
        return {"message": "This is a secure endpoint"}
    raise HTTPException(status_code=401, detail="Invalid credentials")
