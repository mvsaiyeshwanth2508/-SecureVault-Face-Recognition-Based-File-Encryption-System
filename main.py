import os
import base64
import hashlib
from tkinter import *
from tkinter import filedialog, messagebox
from pymongo import MongoClient
from pathlib import Path
from dotenv import load_dotenv
from cryptography.fernet import Fernet
from datetime import datetime
import cv2
import face_recognition

# ============ Load Environment Variables ============
load_dotenv()
uri = os.getenv("MONGO_URI")

if not uri or not uri.startswith(("mongodb://", "mongodb+srv://")):
    raise ValueError("❌ Invalid or missing MONGO_URI in .env file")

print("🔗 MONGO_URI loaded:", uri)

# ============ MongoDB Connection ============
try:
    client = MongoClient(uri)
    db = client["securefiledb"]
    users_collection = db["users"]
    logs_collection = db["logs"]
    print("✅ Connected to MongoDB")
except Exception as e:
    print("❌ MongoDB connection failed:", e)
    exit(1)

# ============ Globals ============
current_user = ""
DOWNLOAD_DIR = os.getenv("DOWNLOAD_DIR") or str(Path.home() / "Downloads")
print("📂 Download Directory:", DOWNLOAD_DIR)
ALLOWED_EXTENSIONS = ['.txt', '.pdf', '.jpg', '.png', '.jpeg', '.docx']

# ============ Auth Functions ============
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def create_user(username, password, security_question, security_answer):
    if users_collection.find_one({"username": username}):
        return False, "⚠️ User already exists."
    user_data = {
        "username": username,
        "password": hash_password(password),
        "security_question": security_question,
        "security_answer": hash_password(security_answer)
    }
    users_collection.insert_one(user_data)
    return True, "✅ Account created successfully!"

def login_user(username, password):
    user = users_collection.find_one({"username": username})
    if not user or user["password"] != hash_password(password):
        return False, "❌ Invalid username or password."
    return True, "✅ Login successful!"

def log_user_action(username, action, filename):
    log_entry = {
        "username": username,
        "action": action,
        "filename": filename,
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    }
    logs_collection.insert_one(log_entry)

# ============ Face Authentication ============
def face_match(username):
    try:
        known_path = f"faces/{username}.jpg"
        if not os.path.exists(known_path):
            print("❌ Stored face image not found.")
            return False

        known_image = face_recognition.load_image_file(known_path)
        known_encoding_list = face_recognition.face_encodings(known_image)
        if not known_encoding_list:
            print("❌ No face found in stored image.")
            return False
        known_encoding = known_encoding_list[0]

        cam = cv2.VideoCapture(0)
        for _ in range(5):  # allow camera to warm up
            ret, frame = cam.read()
        cam.release()

        if not ret:
            print("❌ Failed to read from webcam.")
            return False

        rgb_frame = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)
        unknown_encoding_list = face_recognition.face_encodings(rgb_frame)
        if not unknown_encoding_list:
            print("❌ No face detected in camera frame.")
            return False
        unknown_encoding = unknown_encoding_list[0]

        result = face_recognition.compare_faces([known_encoding], unknown_encoding)
        return result[0]
    except Exception as e:
        print("❌ Face match error:", e)
        return False

def capture_face(username):
    face_folder = "faces"
    os.makedirs(face_folder, exist_ok=True)

    cam = cv2.VideoCapture(0)
    cv2.namedWindow("📸 Capture Face - Press SPACE to save")

    while True:
        ret, frame = cam.read()
        if not ret:
            print("❌ Failed to grab frame.")
            break

        cv2.imshow("📸 Capture Face - Press SPACE to save", frame)
        k = cv2.waitKey(1)
        if k % 256 == 27:
            print("❌ Escape hit, closing...")
            break
        elif k % 256 == 32:
            encodings = face_recognition.face_encodings(frame)
            if not encodings:
                print("❌ No face detected. Try again.")
                continue
            img_path = os.path.join(face_folder, f"{username}.jpg")
            cv2.imwrite(img_path, frame)
            print(f"✅ Face saved as {img_path}")
            break

    cam.release()
    cv2.destroyAllWindows()

# ============ Encryption / Decryption ============
def generate_key(password):
    return base64.urlsafe_b64encode(hashlib.sha256(password.encode()).digest())

def is_allowed_file(file_path):
    _, ext = os.path.splitext(file_path)
    return ext.lower() in ALLOWED_EXTENSIONS

def encrypt_file(file_path, password):
    key = generate_key(password)
    fernet = Fernet(key)
    try:
        with open(file_path, 'rb') as file:
            original = file.read()
    except FileNotFoundError:
        status_var.set("❌ File not found.")
        return
    if not is_allowed_file(file_path):
        status_var.set("❌ File type not allowed for encryption.")
        return
    filename = os.path.basename(file_path)
    output_dir = os.path.join(DOWNLOAD_DIR, "encrypted")
    os.makedirs(output_dir, exist_ok=True)
    encrypted_path = os.path.join(output_dir, filename + '.encrypted')
    with open(encrypted_path, 'wb') as encrypted_file:
        encrypted_file.write(fernet.encrypt(original))
    status_var.set(f"✅ Encrypted and saved: {encrypted_path}")
    log_user_action(current_user, "Encrypt", filename)

def decrypt_file(file_path, password):
    key = generate_key(password)
    fernet = Fernet(key)
    if not file_path.endswith(".encrypted"):
        status_var.set("❌ Only .encrypted files can be decrypted.")
        return
    try:
        with open(file_path, 'rb') as enc_file:
            encrypted_data = enc_file.read()
        decrypted = fernet.decrypt(encrypted_data)
    except Exception:
        status_var.set("❌ Decryption failed. Wrong password or corrupted file.")
        return
    filename = os.path.basename(file_path).replace('.encrypted', '')
    output_dir = os.path.join(DOWNLOAD_DIR, "decrypted")
    os.makedirs(output_dir, exist_ok=True)
    decrypted_path = os.path.join(output_dir, filename)
    with open(decrypted_path, 'wb') as dec_file:
        dec_file.write(decrypted)
    status_var.set(f"✅ Decrypted and saved: {decrypted_path}")
    log_user_action(current_user, "Decrypt", filename)

# ============ GUI ============
def choose_file():
    file_path = filedialog.askopenfilename()
    file_path_var.set(file_path)

def do_encrypt():
    file_path = file_path_var.get()
    password = password_var.get()
    if not file_path or not password:
        status_var.set("❌ Select file and enter password.")
        return
    encrypt_file(file_path, password)

def do_decrypt():
    file_path = file_path_var.get()
    password = password_var.get()
    if not file_path or not password:
        status_var.set("❌ Select file and enter password.")
        return
    decrypt_file(file_path, password)

def launch_main_app():
    global file_path_var, password_var, status_var
    app = Tk()
    app.title("🔐 Secure File Encryptor")
    app.geometry("500x500")

    file_path_var = StringVar()
    password_var = StringVar()
    status_var = StringVar()

    Label(app, text=f"👋 Welcome, {current_user}").pack(pady=10)
    Label(app, text="🔑 Password").pack(pady=5)
    Entry(app, textvariable=password_var, show="*").pack(pady=5)

    Label(app, text="📂 File").pack(pady=5)
    Button(app, text="Browse", command=choose_file).pack(pady=5)
    Label(app, textvariable=file_path_var, wraplength=450).pack(pady=5)

    Button(app, text="Encrypt", bg="green", fg="white", command=do_encrypt).pack(pady=5)
    Button(app, text="Decrypt", bg="blue", fg="white", command=do_decrypt).pack(pady=5)

    def show_user_logs():
        logs = logs_collection.find({"username": current_user})
        log_win = Toplevel()
        log_win.title("🧾 Your Logs")
        text = Text(log_win, width=60, height=20)
        text.pack()
        for log in logs:
            line = f"{log['timestamp']} - {log['action']} - {log['filename']}\n"
            text.insert(END, line)

    Button(app, text="📜 View Logs", command=show_user_logs).pack(pady=5)
    Label(app, textvariable=status_var, fg="purple", wraplength=450).pack(pady=10)

    Button(app, text="🚪 Logout", fg="red", command=lambda: [app.destroy(), show_login_screen()]).pack(pady=10)
    app.mainloop()

def show_login_screen():
    login_win = Tk()
    login_win.title("Secure File Encryptor – Login/Register")
    login_win.geometry("400x500")

    Label(login_win, text="👤 Username").pack()
    username_entry = Entry(login_win)
    username_entry.pack(pady=5)

    Label(login_win, text="🔑 Password").pack()
    password_entry = Entry(login_win, show="*")
    password_entry.pack(pady=5)

    Label(login_win, text="❓ Security Question").pack()
    security_question_entry = Entry(login_win)
    security_question_entry.pack(pady=5)

    Label(login_win, text="📝 Security Answer").pack()
    security_answer_entry = Entry(login_win, show="*")
    security_answer_entry.pack(pady=5)

    feedback_label = Label(login_win, text="", fg="red")
    feedback_label.pack(pady=5)

    def login():
        username = username_entry.get()
        password = password_entry.get()
        if not face_match(username):
            feedback_label.config(text="❌ Face authentication failed!", fg="red")
            return
        success, message = login_user(username, password)
        feedback_label.config(text=message, fg="green" if success else "red")
        if success:
            global current_user
            current_user = username
            login_win.destroy()
            launch_main_app()
        else:
            forgot_btn.pack(pady=5)

    def register():
        username = username_entry.get()
        password = password_entry.get()
        sec_q = security_question_entry.get()
        sec_a = security_answer_entry.get()
        if not all([username, password, sec_q, sec_a]):
            feedback_label.config(text="❌ Fill all registration fields", fg="red")
            return
        capture_face(username)
        success, message = create_user(username, password, sec_q, sec_a)
        feedback_label.config(text=message, fg="green" if success else "red")

    Button(login_win, text="📸 Capture Face", command=lambda: capture_face(username_entry.get())).pack(pady=5)
    Button(login_win, text="Login", command=login).pack(pady=5)
    Button(login_win, text="Register", command=register).pack(pady=5)

    forgot_btn = Button(login_win, text="Forgot Password?", fg="blue", command=forgot_password)
    forgot_btn.pack_forget()
    login_win.mainloop()

def forgot_password():
    reset_win = Toplevel()
    reset_win.title("Reset Password")
    reset_win.geometry("350x300")

    Label(reset_win, text="👤 Username").pack()
    username_fp = Entry(reset_win)
    username_fp.pack(pady=5)

    question_var = StringVar()
    Label(reset_win, textvariable=question_var, wraplength=300, fg="blue").pack(pady=5)

    def load_question():
        user = users_collection.find_one({"username": username_fp.get()})
        if user:
            question_var.set(user.get("security_question", "N/A"))
        else:
            question_var.set("User not found")

    Button(reset_win, text="Load Question", command=load_question).pack(pady=5)

    Label(reset_win, text="📝 Your Answer").pack()
    sec_answer_fp = Entry(reset_win, show="*")
    sec_answer_fp.pack(pady=5)

    Label(reset_win, text="🔑 New Password").pack()
    new_pass_entry = Entry(reset_win, show="*")
    new_pass_entry.pack(pady=5)

    def verify():
        uname = username_fp.get()
        sec_ans = sec_answer_fp.get()
        new_pass = new_pass_entry.get()
        user = users_collection.find_one({"username": uname})
        if not user:
            messagebox.showerror("Error", "User not found")
            return
        if hash_password(sec_ans) != user.get("security_answer", ""):
            messagebox.showerror("Error", "Incorrect security answer")
            return
        users_collection.update_one(
            {"username": uname},
            {"$set": {"password": hash_password(new_pass)}}
        )
        messagebox.showinfo("Success", "✅ Password reset successful!")
        reset_win.destroy()

    Button(reset_win, text="Reset Password", command=verify).pack(pady=10)

# ============ Start App ============
if __name__ == "__main__":
    show_login_screen()
