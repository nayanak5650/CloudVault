# CloudVault – Cloud-Based File Storage and Sharing System

## 1. Project Overview

CloudVault is a cloud-based file storage and sharing web application developed using Python and Flask. It uses Amazon S3 to store files securely and allows authenticated users to upload, download, manage, and share files with other registered users.

## 2. Objectives

- Provide secure cloud-based file storage.
- Enable file upload and download.
- Implement user authentication.
- Protect files using encryption.
- Support controlled file sharing.
- Maintain activity logs.

## 3. Features

- User registration and login.
- Password hashing and session management.
- Amazon S3 cloud storage.
- File encryption and decryption using Fernet.
- Amazon S3 server-side encryption.
- File sharing between registered users.
- Revocation of shared access.
- File deletion and access control.
- Activity logging.
- CSRF protection for form submissions.

## 4. Technologies Used

- Programming language: Python
- Web framework: Flask
- Cloud storage: Amazon S3
- Database: SQLite with Flask-SQLAlchemy
- AWS integration: Boto3
- Encryption: Cryptography (Fernet)
- Front end: HTML and CSS
- Development environment: Visual Studio Code

## 5. Requirements

- Windows, Linux, or another compatible operating system.
- Python 3.12 or a compatible version.
- Internet connection.
- An AWS account with an appropriately configured S3 bucket.
- AWS credentials with the required permissions.

## 6. Installation and Setup

1. Install Python and Visual Studio Code.
2. Open a terminal in the project directory.
3. Create a virtual environment using `python -m venv venv`.
4. Activate it on Windows using `venv\Scripts\activate`.
5. Install the dependencies using `python -m pip install -r requirements.txt`.
6. Configure the required environment variables in a local `.env` file.
7. Configure the S3 bucket, AWS region, and permissions.
8. Run the application using `python app.py`.
9. Open `http://127.0.0.1:5000` in a browser.

## 7. Workflow

User Login → File Upload → Encryption → Amazon S3 Storage → Access Control → File Sharing → Activity Logging

## 8. Testing

The following operations have been tested successfully:

- Login and dashboard access.
- File upload.
- File sharing with another registered user.
- Revocation of shared access.
- File deletion.
- Access restriction for another user's private files.

## 9. Security

CloudVault uses password hashing, authenticated sessions, access checks, Fernet application-level encryption, Amazon S3 server-side encryption, and CSRF protection.

Real AWS credentials, Flask secret keys, and encryption keys must be kept private and must not be included in the submission ZIP.

## 10. Future Enhancements

- AI-powered file organization.
- Multi-cloud storage integration.
- Mobile application.
- Enhanced security mechanisms.
- Automated cloud backup.

## 11. Conclusion

CloudVault demonstrates how cloud storage, authentication, encryption, access control, file sharing, and activity logging can be combined in a web application to provide secure file management.