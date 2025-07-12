import cv2
import io
import os
import base64
import bson
from pymongo import MongoClient
from dotenv import load_dotenv

# Load env and connect
load_dotenv()
MONGO_URI = os.getenv("MONGO_URI")

client = MongoClient(MONGO_URI)
db = client["file_encryption_db"]
faces_collection = db["faces"]

def capture_and_store_face(username):
    cam = cv2.VideoCapture(0, cv2.CAP_DSHOW)

    cv2.namedWindow("📸 Press SPACE to Capture")

    while True:
        ret, frame = cam.read()
        if not ret:
            print("❌ Failed to grab frame.")
            break
        cv2.imshow("📸 Press SPACE to Capture", frame)

        k = cv2.waitKey(1)
        if k % 256 == 27:
            print("❌ ESC pressed. Exiting.")
            break
        elif k % 256 == 32:
            # Convert to bytes (JPG encoded)
            _, buffer = cv2.imencode('.jpg', frame)
            encoded_image = bson.Binary(buffer.tobytes())

            # Store in DB
            faces_collection.replace_one(
                {"username": username},
                {"username": username, "image": encoded_image},
                upsert=True
            )
            print(f"✅ Face stored in MongoDB for user: {username}")
            break

    cam.release()
    cv2.destroyAllWindows()

if __name__ == "__main__":
    user = input("Enter username: ")
    capture_and_store_face(user)
