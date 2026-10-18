import mysql.connector
from cryptography.fernet import Fernet
import os
from dotenv import load_dotenv

load_dotenv()

# --- ENCRYPTION KEY ---
FERNET_KEY = os.getenv('FERNET_KEY').encode()
cipher_suite = Fernet(FERNET_KEY)

db_config = {
    'host': os.getenv('DB_HOST', 'localhost'),
    'user': os.getenv('DB_USER', 'root'),
    'password': os.getenv('DB_PASSWORD'),
    'database': os.getenv('DB_NAME', 'hospital_security_mvp')
}

def get_db_connection():
    return mysql.connector.connect(**db_config)

def log_action(user_id, action, details, ip_address):
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        query = "INSERT INTO audit_logs (user_id, action, details, ip_address) VALUES (%s, %s, %s, %s)"
        cursor.execute(query, (user_id, action, details, ip_address))
        conn.commit()
        cursor.close()
        conn.close()
    except mysql.connector.Error as err:
        print(f"Failed to write to audit log: {err}")