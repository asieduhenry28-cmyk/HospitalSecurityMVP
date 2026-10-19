import os
import psycopg2
from dotenv import load_dotenv

load_dotenv()

# Make sure the URL is inside the quotes, and the next line starts on a new line
DATABASE_URL = "postgresql://hospital_user:3Urp55zHJ2d9mVWIMl321JY1MbUunNMp@dpg-dbai064s728c73aj75v0-a.frankfurt-postgres.render.com/hospital_security_mvp"

conn = psycopg2.connect(DATABASE_URL)
cursor = conn.cursor()

# Drop tables if they exist to start fresh
cursor.execute("""
    DROP TABLE IF EXISTS audit_logs, medical_records, appointments, patients, deleted_users, users CASCADE;
""")

cursor.execute("""
    CREATE TABLE users (
        user_id SERIAL PRIMARY KEY,
        full_name VARCHAR(100) NOT NULL,
        username VARCHAR(50) UNIQUE NOT NULL,
        password_hash VARCHAR(255) NOT NULL,
        role VARCHAR(20) NOT NULL,
        totp_secret VARCHAR(100),
        is_active BOOLEAN DEFAULT TRUE,
        failed_attempts INT DEFAULT 0,
        lockout_until TIMESTAMP NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE patients (
        patient_id SERIAL PRIMARY KEY,
        full_name VARCHAR(100) NOT NULL,
        date_of_birth DATE,
        gender VARCHAR(20),
        contact_number VARCHAR(255),
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE appointments (
        appointment_id SERIAL PRIMARY KEY,
        patient_id INT NOT NULL REFERENCES patients(patient_id),
        doctor_id INT NOT NULL REFERENCES users(user_id),
        appointment_date TIMESTAMP NOT NULL,
        reason VARCHAR(255),
        status VARCHAR(20) DEFAULT 'scheduled'
    );

    CREATE TABLE deleted_users (
        deleted_id SERIAL PRIMARY KEY,
        original_user_id INT,
        full_name VARCHAR(100),
        username VARCHAR(50),
        role VARCHAR(30),
        deleted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        deleted_by INT
    );

    CREATE TABLE audit_logs (
        log_id SERIAL PRIMARY KEY,
        user_id INT REFERENCES users(user_id) ON DELETE SET NULL,
        action VARCHAR(100) NOT NULL,
        details TEXT,
        ip_address VARCHAR(45),
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE medical_records (
        record_id SERIAL PRIMARY KEY,
        patient_id INT NOT NULL REFERENCES patients(patient_id),
        doctor_id INT NOT NULL REFERENCES users(user_id),
        diagnosis TEXT NOT NULL,
        prescription TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
""")

conn.commit()
print("Cloud Database setup complete!")
cursor.close()
conn.close()