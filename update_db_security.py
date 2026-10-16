import mysql.connector

db_config = {
    'host': 'localhost',
    'user': 'root',
    'password': 'Standard0263',  # <--- YOUR REAL MYSQL PASSWORD HERE
    'database': 'hospital_security_mvp'
}

try:
    print("Connecting to database...")
    conn = mysql.connector.connect(**db_config)
    cursor = conn.cursor()
    
    print("Adding 'failed_attempts' column...")
    cursor.execute("ALTER TABLE users ADD COLUMN failed_attempts INT DEFAULT 0;")
    
    print("Adding 'lockout_until' column...")
    cursor.execute("ALTER TABLE users ADD COLUMN lockout_until DATETIME NULL;")
    
    conn.commit()
    print("Success! Database updated for Security Hardening.")
    cursor.close()
    conn.close()
except Exception as e:
    print(f"Error (if it says 'Duplicate column name', it's already fixed!): {e}")