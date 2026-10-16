# 🏥 Hospital Security MVP

A secure, full-stack Hospital Management System built with Python (Flask) and MySQL. This MVP demonstrates enterprise-grade security features including Two-Factor Authentication (2FA), Role-Based Access Control (RBAC), Data Encryption, and Audit Logging.

## 🚀 Features

*   **Secure Authentication:** Passwords are securely hashed using `werkzeug.security` (never stored in plain text).
*   **Two-Factor Authentication (2FA):** Integrated with Google Authenticator using `pyotp` for a second layer of security.
*   **Brute-Force Protection:** Accounts automatically lock for 15 minutes after 3 failed login attempts.
*   **Session Timeout:** Users are automatically logged out after 10 minutes of inactivity.
*   **Role-Based Access Control (RBAC):** Specific permissions for Admins, Doctors, and Receptionists.
*   **Data Encryption at Rest:** Sensitive patient contact information is encrypted in the database using Fernet (AES-128 in CBC mode) from the `cryptography` library.
*   **Audit Logging:** Every critical action (login, patient creation, user deletion, etc.) is logged with the user ID, IP address, and timestamp.
*   **User Management:** Admins can deactivate, activate, or soft-delete users (deleted users are archived, not permanently destroyed).
*   **Database Backup & Restore:** Admins can download a complete `.sql` backup of the system and restore it if needed.
*   **Interactive Dashboard:** Real-time statistics cards for Total Patients, Appointments, and Active Doctors.

## 🛠️ Tech Stack

*   **Backend:** Python 3, Flask
*   **Database:** MySQL
*   **Security & Crypto:** Werkzeug, PyOTP, Cryptography
*   **Frontend:** HTML5, CSS3 (Jinja2 Templating)

## 📋 Prerequisites

Before you begin, ensure you have met the following requirements:
*   Python 3.9 or higher installed.
*   MySQL Server and MySQL Workbench installed.
*   An authenticator app on your phone (e.g., Google Authenticator, Authy).

## ⚙️ Installation & Setup

### 1. Clone the repository
```bash
git clone https://github.com/yourusername/HospitalSecurityMVP.git
cd HospitalSecurityMVP