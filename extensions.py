import psycopg2
from cryptography.fernet import Fernet
import os
from dotenv import load_dotenv

load_dotenv()

# --- ENCRYPTION KEY ---
FERNET_KEY = os.getenv('FERNET_KEY').encode()
cipher_suite = Fernet(FERNET_KEY)

# Render will provide a DATABASE_URL. If not found, fallback to local MySQL (for testing)
DATABASE_URL = os.getenv('DATABASE_URL')

def get_db_connection():
    if DATABASE_URL:
        # Connect to Render PostgreSQL
        return psycopg2.connect(DATABASE_URL)
    else:
        # Fallback for local testing (using the PostgreSQL credentials if you install it locally)
        return psycopg2.connect(
            host=os.getenv('DB_HOST', 'localhost'),
            user=os.getenv('DB_USER', 'postgres'),
            password=os.getenv('DB_PASSWORD'),
            dbname=os.getenv('DB_NAME', 'hospital_security_mvp')
        )

def log_action(user_id, action, details, ip_address):
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        query = "INSERT INTO audit_logs (user_id, action, details, ip_address) VALUES (%s, %s, %s, %s)"
        cursor.execute(query, (user_id, action, details, ip_address))
        conn.commit()
        cursor.close()
        conn.close()
    except Exception as err:
        print(f"Failed to write to audit log: {err}")