
from flask_wtf.csrf import CSRFProtect
from flask import Flask, render_template, request, send_from_directory, session, redirect, url_for, flash
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
import os
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from dotenv import load_dotenv
import boto3
from io import BytesIO
from flask import send_file
from cryptography.fernet import Fernet
load_dotenv()
S3_BUCKET = os.getenv("AWS_S3_BUCKET")
AWS_REGION = os.getenv("AWS_REGION", "ap-south-1")

s3 = boto3.client("s3", region_name=AWS_REGION)
ENCRYPTION_KEY = os.getenv("CLOUDVAULT_ENCRYPTION_KEY")

if not ENCRYPTION_KEY:
    raise RuntimeError("CLOUDVAULT_ENCRYPTION_KEY is missing from .env")

cipher = Fernet(ENCRYPTION_KEY.encode())

app = Flask(__name__)
app.secret_key = os.environ.get("CLOUDVAULT_SECRET_KEY")
csrf = CSRFProtect(app)

if not app.secret_key:
    raise RuntimeError("CLOUDVAULT_SECRET_KEY is missing. Check your .env file.")

app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///cloudvault.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)


class ActivityLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), nullable=False)
    action = db.Column(db.String(100), nullable=False)
    filename = db.Column(db.String(255))
    timestamp = db.Column(
        db.DateTime,
        server_default=db.func.current_timestamp()
    )

class FileShare(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    owner_username = db.Column(db.String(80), nullable=False)
    recipient_username = db.Column(db.String(80), nullable=False)
    filename = db.Column(db.String(255), nullable=False)
    created_at = db.Column(
        db.DateTime,
        server_default=db.func.current_timestamp()
    )



UPLOAD_FOLDER = os.path.join(app.root_path, "uploads")
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
app.config["MAX_CONTENT_LENGTH"] = 5 * 1024 * 1024

@app.errorhandler(413)
def too_large(error):
    return "File too large. Maximum upload size is 5 MB.", 413


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form["username"].strip()
        password = request.form["password"]

        existing_user = User.query.filter_by(username=username).first()

        if existing_user:
            return "Username already exists. Please choose another."

        if not username or len(password) < 8:
            return "Enter a username and a password with at least 8 characters."

        password_hash = generate_password_hash(password)

        new_user = User(
            username=username,
            password_hash=password_hash
        )

        db.session.add(new_user)
        db.session.commit()

        return redirect(url_for("login"))

    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        user = User.query.filter_by(username=username).first()

        if user and check_password_hash(user.password_hash, password):
            session["username"] = user.username
            return redirect(url_for("home"))

        return "Invalid username or password"

    return render_template("login.html")


@app.route("/")
def home():
    if "username" not in session:
        return redirect(url_for("login"))

    username = session["username"]
    user_prefix = secure_filename(username) + "/"

    files = []

    try:
        response = s3.list_objects_v2(
            Bucket=S3_BUCKET,
            Prefix=user_prefix
        )

        for obj in response.get("Contents", []):
            filename = obj["Key"][len(user_prefix):]

            if not filename:
                continue

            size_bytes = obj["Size"]

            if size_bytes < 1024:
                size = f"{size_bytes} B"
            elif size_bytes < 1024 * 1024:
                size = f"{size_bytes / 1024:.2f} KB"
            else:
                size = f"{size_bytes / (1024 * 1024):.2f} MB"

            files.append({
                "name": filename,
                "size": size
            })

    except Exception:
        app.logger.exception("Could not list files from S3")
        flash("Could not load files from cloud storage.", "error")

    logs = ActivityLog.query.filter_by(
        username=username
    ).order_by(
        ActivityLog.timestamp.desc()
    ).limit(10).all()

    shared_files = FileShare.query.filter_by(
        recipient_username=username
    ).order_by(
        FileShare.created_at.desc()
    ).all()
    my_shares = FileShare.query.filter_by(
    owner_username=username
    ).order_by(FileShare.created_at.desc()).all()


    
    return render_template(
        "index.html",
        files=files,
        logs=logs,
        shared_files=shared_files,
        my_shares=my_shares
    )




@app.route("/logout")
def logout():
    session.clear()
    flash("You have logged out successfully.", "success")
    return redirect(url_for("login"))




@app.route("/download/<filename>")
def download_file(filename):
    if "username" not in session:
        return redirect(url_for("login"))

    safe_name = secure_filename(filename)
    if not safe_name or safe_name != filename:
        return "Invalid filename", 400

    username = session["username"]
    user_prefix = secure_filename(username) + "/"
    s3_key = user_prefix + safe_name

    try:
        response = s3.get_object(
            Bucket=S3_BUCKET,
            Key=s3_key
        )

        file_data = response["Body"].read()

        if response.get("Metadata", {}).get("encrypted") == "true":
            file_data = cipher.decrypt(file_data)

        return send_file(
            BytesIO(file_data),
            as_attachment=True,
            download_name=safe_name
        )

    except Exception as e:
        error_code = getattr(e, "response", {}).get(
            "Error", {}
        ).get("Code")

        if error_code in ("404", "NoSuchKey", "NotFound"):
            flash("File not found in your account.", "error")
            return redirect(url_for("home"))

        app.logger.exception("S3 download failed")
        flash("Download failed. Please try again.", "error")
        return redirect(url_for("home"))


@app.route("/share/<filename>", methods=["POST"])
def share_file(filename):
    if "username" not in session:
        return redirect(url_for("login"))

    safe_name = secure_filename(filename)
    if not safe_name or safe_name != filename:
        return "Invalid filename", 400

    owner = session["username"]
    recipient = request.form.get("recipient", "").strip()

    if not recipient:
        flash("Enter the recipient's username.", "error")
        return redirect(url_for("home"))

    if recipient == owner:
        flash("You cannot share a file with yourself.", "error")
        return redirect(url_for("home"))

    recipient_user = User.query.filter_by(
        username=recipient
    ).first()

    if not recipient_user:
        flash("That username does not exist.", "error")
        return redirect(url_for("home"))

    owner_key = secure_filename(owner) + "/" + safe_name

    try:
        s3.head_object(Bucket=S3_BUCKET, Key=owner_key)
    except Exception:
        app.logger.exception("Could not verify file before sharing")
        flash("File not found or cloud storage is unavailable.", "error")
        return redirect(url_for("home"))

    existing_share = FileShare.query.filter_by(
        owner_username=owner,
        recipient_username=recipient,
        filename=safe_name
    ).first()

    if existing_share:
        flash("This file is already shared with that user.", "error")
        return redirect(url_for("home"))

    share = FileShare(
        owner_username=owner,
        recipient_username=recipient,
        filename=safe_name
    )

    db.session.add(share)
    db.session.commit()

    log = ActivityLog(
        username=owner,
        action="File shared",
        filename=safe_name
    )
    db.session.add(log)
    db.session.commit()

    flash("File shared successfully!", "success")
    return redirect(url_for("home"))


@app.route("/revoke-share/<int:share_id>", methods=["POST"])
def revoke_share(share_id):
    if "username" not in session:
        return redirect(url_for("login"))

    username = session["username"]

    share = FileShare.query.filter_by(
        id=share_id,
        owner_username=username
    ).first()

    if not share:
        flash("Share not found or you do not have permission.", "error")
        return redirect(url_for("home"))

    filename = share.filename
    recipient = share.recipient_username

    db.session.delete(share)

    log = ActivityLog(
        username=username,
        action="File sharing revoked",
        filename=filename
    )
    db.session.add(log)
    db.session.commit()

    flash(
        f"Sharing of {filename} with {recipient} has been revoked.",
        "success"
    )
    return redirect(url_for("home"))



@app.route("/shared-download/<owner>/<filename>")
def download_shared_file(owner, filename):
    if "username" not in session:
        return redirect(url_for("login"))

    safe_owner = secure_filename(owner)
    safe_name = secure_filename(filename)

    if safe_owner != owner or safe_name != filename:
        return "Invalid filename or owner", 400

    recipient = session["username"]

    share = FileShare.query.filter_by(
        owner_username=owner,
        recipient_username=recipient,
        filename=safe_name
    ).first()

    if not share:
        return "You are not authorized to access this file.", 403

    s3_key = safe_owner + "/" + safe_name

    try:
        response = s3.get_object(
            Bucket=S3_BUCKET,
            Key=s3_key
        )

        file_data = response["Body"].read()

        if response.get("Metadata", {}).get("encrypted") == "true":
            file_data = cipher.decrypt(file_data)

        return send_file(
            BytesIO(file_data),
            as_attachment=True,
            download_name=safe_name
        )

    except Exception:
        app.logger.exception("Shared file download failed")
        flash("Could not download the shared file.", "error")
        return redirect(url_for("home"))



@app.route("/delete/<filename>", methods=["POST"])
def delete_file(filename):
    if "username" not in session:
        return redirect(url_for("login"))

    safe_name = secure_filename(filename)
    if not safe_name or safe_name != filename:
        return "Invalid filename", 400

    username = session["username"]
    user_prefix = secure_filename(username) + "/"
    s3_key = user_prefix + safe_name

    try:
        s3.head_object(Bucket=S3_BUCKET, Key=s3_key)
        s3.delete_object(Bucket=S3_BUCKET, Key=s3_key)

    except Exception as e:
        error_code = getattr(e, "response", {}).get(
            "Error", {}
        ).get("Code")

        if error_code in ("404", "NoSuchKey", "NotFound"):
            return "File not found", 404

        app.logger.exception("S3 deletion failed")
        flash("Could not delete file. Please try again.", "error")
        return redirect(url_for("home"))

    log = ActivityLog(
        username=username,
        action="File deleted",
        filename=safe_name
    )
    db.session.add(log)
    db.session.commit()

    flash("File deleted successfully!", "success")
    return redirect(url_for("home"))






@app.route("/upload", methods=["POST"])
def upload_file():
    if "username" not in session:
        return redirect(url_for("login"))

    if "file" not in request.files:
        return "No file selected"

    file = request.files["file"]

    if file.filename == "":
        return "No file selected"

    safe_name = secure_filename(file.filename)

    if not safe_name:
        return "Invalid filename"

    username = session["username"]
    user_prefix = secure_filename(username) + "/"
    s3_key = user_prefix + safe_name

    try:
        existing = s3.list_objects_v2(
            Bucket=S3_BUCKET,
            Prefix=s3_key,
            MaxKeys=1
        )

        if any(obj["Key"] == s3_key for obj in existing.get("Contents", [])):
            flash("A file with this name already exists. Please rename it.", "error")
            return redirect(url_for("home"))

        file_data = file.read()
        encrypted_data = cipher.encrypt(file_data)

        s3.put_object(
            Bucket=S3_BUCKET,
            Key=s3_key,
            Body=encrypted_data,
            Metadata={"encrypted": "true"}
        )

    except Exception:
        app.logger.exception("S3 upload failed")
        flash("File upload failed. Please try again.", "error")
        return redirect(url_for("home"))

    log = ActivityLog(
        username=username,
        action="File uploaded",
        filename=safe_name
    )
    db.session.add(log)
    db.session.commit()

    flash("File uploaded successfully to cloud storage!", "success")
    return redirect(url_for("home"))




if __name__ == "__main__":
    with app.app_context():
        db.create_all()

    app.run(debug=True)