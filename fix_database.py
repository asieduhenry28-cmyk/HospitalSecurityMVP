import mysql.connector

db_config = {
    'host': 'localhost',
    'user': 'root',
    'password': 'Standard0263,',  # <--- YOUR REAL MYSQL PASSWORD HERE
    'database': 'hospital_security_mvp'
}

try:
    print("Connecting to database...")
    conn = mysql.connector.connect(**db_config)
    cursor = conn.cursor()
    
    # 1. Fix the column size
    print("Fixing the 'contact_number' column size...")
    cursor.execute("ALTER TABLE patients MODIFY contact_number VARCHAR(255);")
    conn.commit()
    print("Success! Column size updated.")
    
    # 2. Verify it worked
    print("Verifying the change...")
    cursor.execute("DESCRIBE patients;")
    columns = cursor.fetchall()
    for col in columns:
        if col[0] == 'contact_number':
            print(f"PERFECT! 'contact_number' is now type: {col[1]}")
            
    cursor.close()
    conn.close()
    print("\nEverything is fixed! Go back to your browser and try saving the patient again.")
    
except Exception as e:
    print(f"\nError: {e}")
    print("Make sure MySQL Workbench is completely CLOSED.")