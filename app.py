from flask import Flask, request, jsonify, url_for, send_from_directory, session
from flask_migrate import Migrate
from flask_session import Session
from flask_login import LoginManager, UserMixin, login_user, login_required, current_user, logout_user
from functools import wraps
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import ForeignKey, Date
from sqlalchemy.orm import relationship
from flask_cors import CORS, cross_origin
import bcrypt
import os
import re
from PyPDF2 import PdfReader
from fuzzywuzzy import fuzz
from dotenv import load_dotenv
from sqlalchemy import Date
from datetime import datetime
import uuid
import logging
import json_log_formatter
from flask import Flask, request, jsonify, url_for, send_from_directory, session
import redis
from datetime import datetime, timedelta
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from enum import Enum
import openai
from io import StringIO
import PyPDF2
import re
from dateutil.parser import parse as parse_date
import requests
from sqlalchemy.orm import sessionmaker
from flask_mail import Mail, Message


class CustomJSONFormatter(json_log_formatter.JSONFormatter):
    def json_record(self, message, extra, record):
        extra['message'] = message
        return extra

# Configure your Flask app to use this logger
formatter = CustomJSONFormatter()

json_handler = logging.StreamHandler()
json_handler.setFormatter(formatter)

logger = logging.getLogger('my_json')
logger.addHandler(json_handler)
logger.setLevel(logging.INFO)

app = Flask(__name__)
CORS(app, origins='http://localhost:3000', supports_credentials=True)
app.config["SQLALCHEMY_DATABASE_URI"] = 'postgresql://mezz_a8l8_user:mp2XYTZur9h5Okxk9KnnoLQ7yVWB9xuv@dpg-cnd2fv2cn0vc73f4rj9g-a.oregon-postgres.render.com/mezz_a8l8'
# 'postgresql://shreeya:GTKvyyIQBPdE2lWnD80WhuhVm8JCtJ2B@dpg-clso8ftcm5oc73b94350-a.oregon-postgres.render.com/mezzprofinal'
load_dotenv()
app.config['UPLOAD_FOLDER'] = os.path.join('.', 'pdfs')
db = SQLAlchemy(app)
app.secret_key = '6de23aa303c89bb1ab31a42a39b419ba3ce26cae8821cfa7c060878c63b827b1'


app.config['MAIL_SERVER'] = 'smtp.example.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'your-email@example.com'
app.config['MAIL_PASSWORD'] = 'your-password'
app.config['MAIL_DEFAULT_SENDER'] = 'your-email@example.com'
mail = Mail(app)

# Configure Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)

# # Define your OpenAI GPT-3 API key
openai.api_key = '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'
client = openai

#GSTIN api token
api_token ="eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJmcmVzaCI6ZmFsc2UsImlhdCI6MTY0OTg0MDE3MSwianRpIjoiYjNhNmJjNmItNzE1Yy00OTU0LThkNTgtMTI4ODY5NWM5MTA1IiwidHlwZSI6ImFjY2VzcyIsImlkZW50aXR5IjoiZGV2Lm1pbnFyb0BhYWRoYWFyYXBpLmlvIiwibmJmIjoxNjQ5ODQwMTcxLCJleHAiOjE5NjUyMDAxNzEsInVzZXJfY2xhaW1zIjp7InNjb3BlcyI6WyJyZWFkIl19fQ.8KK8EnikhK58RtPtjV_oTl2qcs8YaZTtGgZBjjEl3vk"

#API_KEY for IRN validation 
api_key = "AL8n2R0O1b8R5E9I7B"
# Initialize JWT
jwt = JWTManager(app)

migrate = Migrate(app, db)

# ===================Models==================

from enum import Enum , unique

@unique
class InvoiceStatus(Enum):
    APPROVED = "Approved"
    TOKENIZED = "Tokenized"
    EARLY_PAYMENT = "Early Payment"
    COMPLETED = "Completed"


class UserRole(Enum):
    MEZZPRO_ADMIN = "Mezzpro Admin"
    LENDER_ADMIN = "Lender Admin"
    BIZ_ADMIN = "Biz admin"
    SELLER = "Seller"
    BUYER = "Buyer"

class User(UserMixin, db.Model):
    id = db.Column(db.Integer(), primary_key=True, nullable=False, autoincrement=True)
    username = db.Column(db.String(100), unique=True)
    first_name = db.Column(db.String(100))
    last_name = db.Column(db.String(100))
    email = db.Column(db.String, unique=True)
    password = db.Column(db.String(100))
    address = db.Column(db.String(500))
    mobile_no = db.Column(db.String(100), unique=True)

    # ====Bank details=====
    bank_name = db.Column(db.String(100))
    branch = db.Column(db.String(100))
    ifsc_code = db.Column(db.String(100))
    account_number = db.Column(db.String(100))
    bank_balance = db.Column(db.Float(), default=0.0)

    gstin = db.Column(db.String(100))

    # ====kyc====
    pan_number = db.Column(db.String(100))

    #====Wallet address=====
    metamask_address = db.Column(db.String(100), unique=True, nullable=False)

    # Updated role field to use enumeration
    role = db.Column(db.Enum(UserRole))

    #======Comapny======
    company_id = db.Column(db.Integer, db.ForeignKey('company_user.id'), nullable=True)
    company = db.relationship('Company_User', backref=db.backref('users', lazy=True))
    # Define the relationship to approved buyers
    approved_buyers = db.relationship(
        'BuyerDetails',
        back_populates='lender',
        foreign_keys='BuyerDetails.lender_id',  # Specify the foreign key
        uselist=False
    )

class Company_User(db.Model):
    id = db.Column(db.Integer(), primary_key=True, nullable=False, autoincrement=True)
    client_id = db.Column(db.String(100), unique=True)
    gstin = db.Column(db.String(100), unique=True)
    pan_number = db.Column(db.String(100), unique=True)
    business_name = db.Column(db.String(100))
    legal_name = db.Column(db.String(100))
    center_jurisdiction = db.Column(db.String(500))
    state_jurisdiction = db.Column(db.String(500))
    date_of_registration = db.Column(db.Date())
    constitution_of_business = db.Column(db.String(100))
    taxpayer_type = db.Column(db.String(100))
    gstin_status = db.Column(db.String(100))
    date_of_cancellation = db.Column(db.Date())
    field_visit_conducted = db.Column(db.String(100))
    nature_of_core_business_activity_code = db.Column(db.String(100))
    nature_of_core_business_activity_description = db.Column(db.String(500))
    aadhaar_validation = db.Column(db.String(100))
    aadhaar_validation_date = db.Column(db.Date())
    address = db.Column(db.String(500))
    # Consider how to model the nature_bus_activities and filing_status as they are lists


class Invoice(db.Model):
    id = db.Column(db.Integer(), primary_key=True, autoincrement=True)
    user_id = db.Column(db.Integer(), ForeignKey('user.id'), nullable=False)
    invoice_id = db.Column(db.String(100))
    total_amount = db.Column(db.Float())
    due_date = db.Column(Date)
    buyer_id = db.Column(db.Integer(), ForeignKey('user.id'), nullable=False)
    buyer_metamask_address = db.Column(db.String(100), ForeignKey('user.metamask_address'), nullable=False)
    pdf_url = db.Column(db.String(200))
    approval_status = db.Column(db.Boolean(), default=False)
    metamask_address = db.Column(db.String(100))
    buyer_details_id = db.Column(db.Integer(), ForeignKey('buyer_details.id'))
    status = db.Column(db.Enum(InvoiceStatus), nullable=True)
    approved_lender_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    

    # Define relationships
    user = relationship('User', foreign_keys=[user_id])
    buyer = relationship('User', foreign_keys=[buyer_id], backref='invoices_as_buyer')
    buyer_details = relationship('BuyerDetails', backref='invoices')
    approved_lender = db.relationship('User', foreign_keys=[approved_lender_id], backref='approved_invoices')
 

     
class SentForApproval(db.Model):
    id = db.Column(db.Integer(), primary_key=True, autoincrement=True)
    invoice = db.Column(db.Integer(), db.ForeignKey('invoice.id'), nullable=False)
    user_id = db.Column(db.Integer(), db.ForeignKey('user.id'), nullable=False)
    buyer_id = db.Column(db.Integer(), db.ForeignKey('user.id'), nullable=False)
    buyer_metamask_address = db.Column(db.String(100), db.ForeignKey('user.metamask_address'), nullable=False)# Adding the buyer's metamask address field
    approve_status = db.Column(db.Boolean(), default=False)


class EscrowAccount(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False, unique=True)
    balance = db.Column(db.Float, default=0.0)
    bank_name = db.Column(db.String(100), nullable=True)
    account_number = db.Column(db.String(100), nullable=True)
    
    user = db.relationship('User', backref=db.backref('escrow_account', uselist=False))


class Transaction(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('escrow_account.id'), nullable=False)
    receiver_id = db.Column(db.Integer, db.ForeignKey('escrow_account.id'), nullable=False)
    amount = db.Column(db.Float, nullable=False)
    transaction_date = db.Column(db.DateTime, default=datetime.utcnow)
    status = db.Column(db.String(50), nullable=False)

    sender = db.relationship('EscrowAccount', foreign_keys=[sender_id], backref='sent_transactions')
    receiver = db.relationship('EscrowAccount', foreign_keys=[receiver_id], backref='received_transactions')

class BuyerDetails(db.Model):
    id = db.Column(db.Integer(), primary_key=True)
    user_id = db.Column(db.Integer(), db.ForeignKey('user.id'), unique=True)
    total_balance = db.Column(db.Float(), default=0.0)
    buyer_category = db.Column(db.String(100))  # e.g., 'Qualified', 'Confirmed', 'Approved'
    lender_id = db.Column(db.Integer(), db.ForeignKey('user.id'), nullable=True)  # Link to lender who approved
    funded_amount = db.Column(db.Float(), default=0.0)  # Amount the lender is willing to fund
    funding_status = db.Column(db.String(100), default='Not Funded')  # Funding status, default is 'Not Funded'

    user = db.relationship('User', foreign_keys=[user_id], backref='buyer_details')
    lender = db.relationship('User', foreign_keys=[lender_id], back_populates='approved_buyers', uselist=False)  # Relationship to lender

    def update_total_balance(self):
        # Logic to update the total balance based on invoices
        self.total_balance = sum(invoice.total_amount for invoice in self.user.invoices_as_buyer if invoice.approval_status)
        db.session.commit()

    def get_detailed_info(self):
        invoices = Invoice.query.filter_by(buyer_id=self.user_id).all()
        invoice_details = [
            {
                'invoice_id': invoice.invoice_id,
                'total_amount': invoice.total_amount,
                'due_date': invoice.due_date.strftime("%Y-%m-%d"),
                'approval_status': invoice.approval_status
            }
            for invoice in invoices
        ]
        return {
            'buyer_id': self.user_id,
            'total_balance': self.total_balance,
            'buyer_category': self.buyer_category,
            'invoices': invoice_details
        }

    db.session.commit()







@app.route('/')
def hello_world():
    db.create_all()
    return 'Hello, World!'




# ========Register and Login ==================


@app.route('/company-register', methods=['POST'])
def company_register():
    data = request.json
    gstin = data.get('gstin')
    if gstin and validate_gstin(gstin):
        return fetch_and_store_company_data(gstin)
    else:
        return jsonify({"error": "Invalid GSTIN provided."}), 400

def validate_gstin(gstin):
    """Validate GSTIN format."""
    pattern = r'^\d{2}[A-Z]{5}\d{4}[A-Z]{1}[A-Z\d]{1}[Z]{1}[A-Z\d]{1}$'
    return bool(re.match(pattern, gstin))

API_URL = "https://kyc-api.aadhaarkyc.io/api/v1/corporate/gstin"

def fetch_and_store_company_data(gstin):
    headers = {'Content-Type': 'application/json', 'Authorization': 'Bearer YOUR_API_TOKEN'}  # Replace YOUR_API_TOKEN with your actual API token
    response = requests.get(f"{API_URL}/{gstin}", headers=headers)
    if response.status_code == 200:
        company_data = response.json()['data']
        store_company_data(company_data)
        return jsonify({"success": "Company data fetched and stored successfully."})
    else:
        return jsonify({"error": "Failed to fetch company data."}), response.status_code


def store_company_data(data):
    # Convert string dates to datetime objects
    date_of_registration = datetime.strptime(data.get('date_of_registration', '1800-01-01'), '%Y-%m-%d').date()
    date_of_cancellation = data.get('date_of_cancellation', None)
    if date_of_cancellation and date_of_cancellation != '1800-01-01':
        date_of_cancellation = datetime.strptime(date_of_cancellation, '%Y-%m-%d').date()
    else:
        date_of_cancellation = None  # Handle the '1800-01-01' placeholder as None

    aadhaar_validation_date = datetime.strptime(data.get('aadhaar_validation_date', '1800-01-01'), '%Y-%m-%d').date()

    company = Company_User(
        client_id=data.get('client_id'),
        gstin=data.get('gstin'),
        pan_number=data.get('pan_number'),
        business_name=data.get('business_name'),
        legal_name=data.get('legal_name'),
        center_jurisdiction=data.get('center_jurisdiction'),
        state_jurisdiction=data.get('state_jurisdiction'),
        date_of_registration=date_of_registration,
        constitution_of_business=data.get('constitution_of_business'),
        taxpayer_type=data.get('taxpayer_type'),
        gstin_status=data.get('gstin_status'),
        date_of_cancellation=date_of_cancellation,
        field_visit_conducted=data.get('field_visit_conducted'),
        nature_of_core_business_activity_code=data.get('nature_of_core_business_activity_code'),
        nature_of_core_business_activity_description=data.get('nature_of_core_business_activity_description'),
        aadhaar_validation=data.get('aadhaar_validation'),
        aadhaar_validation_date=aadhaar_validation_date,
        address=data.get('address'),
    )
    db.session.add(company)
    db.session.commit()





@app.route('/register', methods=['POST'])
def register_user():
    data = request.get_json()
    username = data.get('username')
    first_name = data.get('first_name')
    last_name = data.get('last_name')
    email = data.get('email')
    password = data.get('password')
    confirmPassword = data.get('confirmPassword')
    address = data.get('address')
    mobile_no = data.get('mobile_no')
    bank_name = data.get('bank_name')
    branch = data.get('branch')
    ifsc_code = data.get('ifsc_code')
    account_number = data.get('account_number')
    bank_balance = data.get('bank_balance', 0.0)
    company_id = data.get('company_id')
    gstin = data.get('gstin')  
    pan_number = data.get('pan_number')
    metamask_address = data.get('metamask_address')
    role = data.get('role')

    # Add length validation
    if len(username) > 100 or len(email) > 100 or len(password) > 100:
        return jsonify({'error': 'Field length exceeds the maximum limit'}), 400

    if not (username and first_name and last_name and email and password and address and mobile_no and confirmPassword and bank_name and branch and ifsc_code and account_number and company_id and gstin and pan_number and metamask_address):
        return jsonify({'error': 'Missing required fields'}), 400

    if User.query.filter((User.username == username) | (User.email == email)).first():
        return jsonify({'error': 'Username or email already exists'}), 409

    if password != confirmPassword:
        return jsonify({'error': 'Passwords do not match'}), 400

    # Validate GSTIN
    if not validate_gstin(gstin, api_token):
        return jsonify({'error': 'Invalid GSTIN'}), 400

    # Use Flask-Bcrypt for password hashing
    salt = bcrypt.gensalt()
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), salt).decode('utf-8')

    new_user = User(
        username=username,
        first_name=first_name,
        last_name=last_name,
        email=email,
        password=hashed_password,
        address=address,
        mobile_no=mobile_no,
        bank_name=bank_name,
        branch=branch,
        ifsc_code=ifsc_code,
        account_number=account_number,
        bank_balance=bank_balance,
        company_id = company_id,
        gstin=gstin,# Renamed from 'tin' to 'gstin'
        pan_number=pan_number,
        metamask_address=metamask_address,
        role=role,
    )

    db.session.add(new_user)
    db.session.commit()

    # Create a JWT token for the new user
    access_token = create_access_token(identity=new_user.id)
    return jsonify({'message': 'User registered successfully!', 'access_token': access_token}), 201



@app.route('/login', methods=['POST'])

def login():

    data = request.get_json()

    username = data.get('username')

    password = data.get('password')

    user = User.query.filter_by(username=username).first()

    if user and bcrypt.checkpw(password.encode('utf-8'), user.password.encode('utf-8')):

        access_token = create_access_token(identity=user.id, additional_claims={'role': user.role.value})

        logger.info(f"User {username} logged in successfully with user ID: {user.id}")

        return jsonify({'message': 'Login successful', 'access_token': access_token, 'role': user.role.value}), 200

    else:

        logger.warning(f"Failed login attempt for username: {username}")

        return jsonify({'error': 'Invalid username or password'}), 401


@app.route('/check-auth', methods=['GET'])
@jwt_required()
def check_auth():
    user_id = get_jwt_identity()
    logger.info(f"JWT User ID: {user_id}")

    user = User.query.get(user_id)
    if user:
        logger.info(f"User {user.username} is authenticated and found in the database")
        return jsonify({
            'message': 'Authenticated',
            'username': user.username,
            'email': user.email
        }), 200
    else:
        logger.warning(f"User ID {user_id} not found in database")
        return jsonify({'error': 'User not found in database'}), 404

@app.route('/logout', methods=['POST'])
def logout():
    # JWT is stateless, logout is handled client-side
    logger.info("Logout requested")
    return jsonify({'message': 'Logged out successfully'}), 200

# ============Dashboard part===============


@app.route('/dashboard')
@jwt_required()
def dashboard():
    return 'Welcome to the dashboard!'

# ====== User role management =============

# ====== USER ROLE AS MEZZPRO-ADMIN =============

def get_system_statistics():
    total_users = User.query.count()
    total_invoices = Invoice.query.count()
    total_tokenized_amount = db.session.query(db.func.sum(Invoice.total_amount)).filter(Invoice.approval_status == True).scalar()

    # Assuming 'total_tokenized_amount' might be None if no invoices are tokenized yet.
    total_tokenized_amount = total_tokenized_amount or 0

    return {
        'total_users': total_users,
        'total_invoices': total_invoices,
        'total_tokenized_amount': total_tokenized_amount
    }

def get_transaction_data():
    recent_transactions = Invoice.query.order_by(Invoice.due_date.desc()).limit(50)  # Adjust the limit as needed
    transactions_list = []

    for transaction in recent_transactions:
        transaction_info = {
            'invoice_id': transaction.invoice_id,
            'user_id': transaction.user_id,
            'buyer_id': transaction.buyer_id,
            'total_amount': transaction.total_amount,
            'due_date': transaction.due_date.strftime("%Y-%m-%d"),
            'approval_status': transaction.approval_status,
            'pdf_url': transaction.pdf_url,
            # Add other relevant fields as required
        }
        transactions_list.append(transaction_info)

    return {
        'recent_transactions': transactions_list
    }

class AuditLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    action = db.Column(db.String(255))
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

    user = relationship('User', backref='audit_logs')

def get_audit_trails():
    audit_logs = AuditLog.query.order_by(AuditLog.timestamp.desc()).all()
    logs_list = [ ... ]  # process logs into a list of dictionaries
    return {
        'total_logs': len(logs_list),
        'logs': logs_list
    }

# ====== USER-ROLE =============
@app.route('/user_role', methods=['GET'])
@jwt_required()
def get_user_role():
    user_id = get_jwt_identity()
    user = User.query.get(user_id)

    if user:
        return jsonify({'user_role': user.role.name}), 200
    else:
        return jsonify({'error': 'User not found'}), 404



# ====== profilepage =============


@app.route('/profile', methods=['GET'])
@jwt_required()
def profile():
    user_id = get_jwt_identity()
    user = User.query.get(user_id)
    if user:
        profile_data = {
            'sessionID': user.id,
            'username': user.username,
            'first_name': user.first_name,
            'last_name': user.last_name,
            'email': user.email,
            'address': user.address,
            'mobile_no': user.mobile_no,
            'bank_name': user.bank_name,
            'branch': user.branch,
            'ifsc_code': user.ifsc_code,
            'account_number': user.account_number,
            'bank_balance' : user.bank_balance,
            'company_name': user.company_name,
            'gstin': user.gstin,
            'pan_number': user.pan_number,
            'metamask_address': user.metamask_address,
            'role' : user.role.name if user.role else None

        }
        return jsonify(profile_data), 200
    else:
        return jsonify({'error': 'User not found'}), 404

@app.route('/update_profile', methods=['PUT'])
@jwt_required()  # This decorator ensures that a valid JWT token is required for access
def update_profile():
    user_id = get_jwt_identity()
    user = User.query.get(user_id)
  # Implement a function to get the current user from the JWT token
    data = request.get_json()
    if not user:
        return jsonify({'message': 'User not authenticated'}), 401

    user.username = data.get('username', user.username)
    user.first_name = data.get('first_name', user.first_name)
    user.last_name = data.get('last_name', user.last_name)
    user.email = data.get('email', user.email)
    user.address = data.get('address', user.address)
    user.mobile_no = data.get('mobile_no', user.mobile_no)
    user.bank_name = data.get('bank_name', user.bank_name)
    user.branch = data.get('branch', user.branch)
    user.ifsc_code = data.get('ifsc_code', user.ifsc_code)
    user.account_number = data.get('account_number', user.account_number)
    user.bank_balance = data.get('bank_balance', user.bank_balance)
    user.company_name = data.get('company_name', user.company_name)
    user.gstin = data.get('gstin', user.gstin)
    user.pan_number = data.get('pan_number', user.pan_number)
    user.metamask_address = data.get('metamask_address', user.metamask_address)
    user.role = data.get('role', user.role)

    db.session.commit()

    profile_data = {
        'id': user.id,
        'username': user.username,
        'first_name': user.first_name,
        'last_name': user.last_name,
        'email': user.email,
        'address': user.address,
        'mobile_no': user.mobile_no,
        'bank_name': user.bank_name,
        'branch': user.branch,
        'ifsc_code': user.ifsc_code,
        'account_number': user.account_number,
        'bank_balance' : user.bank_balance,
        'company_name': user.company_name,
        'gstin': user.gstin,
        'pan_number': user.pan_number,
        'metamask_address': user.metamask_address,
        'role': user.role
    }
    return jsonify(profile_data), 200

# ================Invoice Handling  ==================


def convert_pdf_to_text(pdf_path):
    text = ''
    with open(pdf_path, 'rb') as pdf_file:
        pdf_reader = PdfReader(pdf_file)
        for pdf_page in pdf_reader.pages:
            text += pdf_page.extract_text()

    return text

def extract_text_from_pdf(pdf_path):
    text = ""
    with open(pdf_path, "rb") as f:
        pdf = PyPDF2.PdfReader(f)
        for page in pdf.pages:
            text += page.extract_text()
    return text

def parse_gpt_response(gpt_response):
    # Regular expressions to match invoice ID, due date, and total amount
    invoice_id_regex = r"Invoice ID: (\S+)"
    due_date_regex = r"Due Date: ([\w\s]+)"
    total_amount_regex = r"Total Amount: ([\S ]+)"

    # Extracting invoice ID
    invoice_id_match = re.search(invoice_id_regex, gpt_response)
    invoice_id = invoice_id_match.group(1) if invoice_id_match else None

    # Extracting due date and attempting to convert to 'dd-mm-yyyy' format
    due_date_match = re.search(due_date_regex, gpt_response)
    due_date_str = due_date_match.group(1) if due_date_match else None
    try:
        due_date = parse_date.parse(due_date_str).strftime('%d-%m-%Y') if due_date_str else None
    except:
        due_date = None  # or some default or error handling

    # Extracting total amount and cleaning the string
    total_amount_match = re.search(total_amount_regex, gpt_response)
    if total_amount_match:
        total_amount_str = total_amount_match.group(1)
        # Removing currency symbols and commas
        cleaned_total_amount = re.sub(r'[^\d.]', '', total_amount_str)
        total_amount = float(cleaned_total_amount) if cleaned_total_amount else None
    else:
        total_amount = None

    return invoice_id, due_date, total_amount

def parse_invoice_test_response(gpt_response):
    # Regular expressions to match invoice ID, total amount, company names, and GSTINs
    invoice_id_regex = r"Invoice ID: (\S+)"
    total_amount_regex = r"Total Amount: ([\S ]+)"
    seller_company_regex = r"Seller Company Name: (.+)"
    buyer_company_regex = r"Buyer Company Name: (.+)"
    seller_gstin_regex = r"Seller GSTIN: (\S+)"
    buyer_gstin_regex = r"Buyer GSTIN: (\S+)"

    # Extracting invoice ID
    invoice_id_match = re.search(invoice_id_regex, gpt_response)
    invoice_id = invoice_id_match.group(1) if invoice_id_match else None

    # Extracting total amount
    total_amount_match = re.search(total_amount_regex, gpt_response)
    total_amount = total_amount_match.group(1) if total_amount_match else None

    # Extracting seller company name
    seller_company_match = re.search(seller_company_regex, gpt_response)
    seller_company = seller_company_match.group(1) if seller_company_match else None

    # Extracting buyer company name
    buyer_company_match = re.search(buyer_company_regex, gpt_response)
    buyer_company = buyer_company_match.group(1) if buyer_company_match else None

    # Extracting seller GSTIN
    seller_gstin_match = re.search(seller_gstin_regex, gpt_response)
    seller_gstin = seller_gstin_match.group(1) if seller_gstin_match else None

    # Extracting buyer GSTIN
    buyer_gstin_match = re.search(buyer_gstin_regex, gpt_response)
    buyer_gstin = buyer_gstin_match.group(1) if buyer_gstin_match else None

    return invoice_id, total_amount, seller_company, buyer_company, seller_gstin, buyer_gstin

def validate_gstin(gstin, api_token):
    if not gstin:
        return False

    api_url = "https://kyc-api.aadhaarkyc.io/api/v1/corporate/gstin"
    headers = {'Authorization': f'Bearer {api_token}', 'Content-Type': 'application/json'}
    data = {'id_number': gstin, 'filing_status_get': True}  # Use JSON data for POST requests

    try:
        response = requests.post(api_url, headers=headers, json=data)
        print("API Request:", response.url)  # Debugging: print the API request URL
        print("API Response:", response.json())  # Debugging: print the API response
        
        if response.status_code == 200:
            success_status = response.json().get('success', False)
            return success_status
        else:
            return False
    except requests.RequestException as e:
        print("API Request Exception:", e)  # Debugging: print any exceptions
        return False




def validate_irn(doc_type, doc_num, doc_date, auth_token):
    api_url = f"https://developers.eraahi.com/eInvoiceGateway/eicore/v1.03/Invoice/irnbydocdetails"
    headers = {
        'client_id': '07AGAPA5363L002',
        'client_secret': 'Alankit@123',
        'Gstin': '07AGAPA5363L002',
        'user_name': 'AL001',
        'AuthToken': '3Bti0x7nQNBRATQOmOiNKv2vU'
    }

    try:
        print(f"IRN Validation: Sending request to {api_url}")
        response = requests.get(api_url, headers=headers)
        print(f"IRN Validation: Received response with status code {response.status_code}")

        if response.status_code == 200:
            response_json = response.json()
            print(f"IRN Validation: Response JSON - {response_json}")

            if response_json.get('Status') == "1":
                print("IRN Validation: IRN is valid.")
                return True
            else:
                print("IRN Validation: IRN is not valid.")
                return False
        else:
            print(f"IRN Validation: Non-200 response received. Response: {response.text}")
            return False
    except requests.RequestException as e:
        print(f"IRN Validation: API Request Exception - {e}")
        return False


@app.route('/test_invoice', methods=['POST'])
def test_invoice():
    # Check if the invoice file is present in the request
    if 'invoice_file' not in request.files:
        return jsonify({'error': 'No file uploaded'}), 400

    invoice_file = request.files['invoice_file']
    if invoice_file.filename == '':
        return jsonify({'error': 'No selected file'}), 400

    # Save the uploaded invoice file
    unique_filename = str(uuid.uuid4()) + '.pdf'
    uploaded_pdf_path = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
    invoice_file.save(uploaded_pdf_path)

    # Extract text from the PDF
    extracted_text = convert_pdf_to_text(uploaded_pdf_path)

    # Prepare and send the request to OpenAI's ChatCompletion
    system_message_content = "Extract the seller and buyer company names, their GSTIN numbers, invoice ID, and total amount from the following text."
    user_message_content = extracted_text
    response = openai.ChatCompletion.create(
        model="gpt-4-1106-preview",
        messages=[
            {"role": "system", "content": system_message_content},
            {"role": "user", "content": user_message_content}
        ]
    )

    # Extract response from OpenAI's model
    gpt_response = response['choices'][0]['message']['content'].strip()

    # Parse the response to get invoice details
    invoice_id, total_amount, seller_company, buyer_company, seller_gstin, buyer_gstin = parse_invoice_test_response(gpt_response)

    # Validate GSTINs
    
    seller_gstin_valid = validate_gstin(seller_gstin, api_token)
    buyer_gstin_valid = validate_gstin(buyer_gstin, api_token)

   
    # Directly use the auth token if you already have it
    auth_token = "3Bti0x7nQNBRATQOmOiNKv2vU"  # Replace with your actual token

    # Validate IRN
    doc_type = "INV"  # Replace with the actual document type expected by the API
    doc_num = "4756614412"
    doc_date = "2023-06-30"
    irn_valid = validate_irn(doc_type, doc_num, doc_date, auth_token)

    # Prepare the response data
    response_data = {
        'invoice_id': invoice_id,
        'total_amount': total_amount,
        'seller_company_name': seller_company,
        'buyer_company_name': buyer_company,
        'seller_gstin': seller_gstin,
        'buyer_gstin': buyer_gstin,
        'seller_gstin_valid': seller_gstin_valid,
        'buyer_gstin_valid': buyer_gstin_valid,
        'irn_valid': irn_valid
    }

    return jsonify(response_data), 200

def resolve_gstin_to_email(gstin):
    company = Company_User.query.filter_by(gstin=gstin).first()
    return company.email if company else None

def is_entity_registered(gstin):
    # Query your database to check if a company with the given GSTIN exists
    company = Company_User.query.filter_by(gstin=gstin).first()
    return company is not None

def prompt_for_registration(seller_company, seller_gstin, buyer_company, buyer_gstin):
    # Example email content. Customize this according to your needs.
    subject = "Invitation to Register"
    
    # Assuming you have a way to resolve GSTINs to email addresses
    seller_email = resolve_gstin_to_email(seller_gstin)
    buyer_email = resolve_gstin_to_email(buyer_gstin)
    
    # Email body. Customize this with actual registration instructions or links.
    body = f"Dear {seller_company} and {buyer_company},\n\n" \
           "You are invited to register on our platform. Please follow the link to complete your registration.\n\n" \
           "Best regards,\nYour Company Name"
    
    if seller_email:
        send_email(seller_email, subject, body)
    if buyer_email:
        send_email(buyer_email, subject, body)

def send_email(to, subject, body):
    msg = Message(subject, recipients=[to], body=body)
    mail.send(msg)


@app.route('/upload_invoice', methods=['POST'])
# @jwt_required()  # Uncomment this if JWT authentication is set up
def upload_invoice():
    if 'invoice_file' not in request.files:
        return jsonify({'error': 'No file uploaded'}), 400

    invoice_file = request.files['invoice_file']
    if invoice_file.filename == '':
        return jsonify({'error': 'No selected file'}), 400

    unique_filename = str(uuid.uuid4()) + '.pdf'
    uploaded_pdf_path = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
    invoice_file.save(uploaded_pdf_path)

    extracted_text = convert_pdf_to_text(uploaded_pdf_path)

    # Ensure your OpenAI API key is correctly set in your environment or configuration
 
    response = openai.ChatCompletion.create(
        model="gpt-4",  # Update the model name if needed
        messages=[
            {"role": "system", "content": "Extract the seller and buyer company names, their GSTIN numbers, invoice ID, due date, and total amount from the following text. Convert any dates into the format 'dd-mm-yyyy'."},
            {"role": "user", "content": extracted_text}
        ]
    )

    gpt_response = response['choices'][0]['message']['content'].strip()
    # Assuming parse_gpt_response is tailored to parse the updated GPT response
    parsed_data = parse_gpt_response(gpt_response)
    invoice_id, due_date, total_amount, seller_company, buyer_company, seller_gstin, buyer_gstin = parsed_data

    # Check if seller and buyer are registered entities
    seller_registered = is_entity_registered(seller_gstin)
    buyer_registered = is_entity_registered(buyer_gstin)

    # Handle non-registered entities
    if not seller_registered or not buyer_registered:
        # Implement logic to prompt for registration or to send an invitation
        prompt_for_registration(seller_company, seller_gstin, buyer_company, buyer_gstin)

    response_data = {
        'invoice_id': invoice_id,
        'due_date': due_date.strftime('%d-%m-%Y') if due_date else None,
        'total_amount': total_amount,
        'seller_company': seller_company,
        'buyer_company': buyer_company,
        'seller_gstin': seller_gstin,
        'buyer_gstin': buyer_gstin,
        'seller_registered': seller_registered,
        'buyer_registered': buyer_registered,
        'pdf_url': url_for('uploaded_pdf', filename=unique_filename, _external=True)  # Assuming there's an endpoint to serve the uploaded files
    }

    return jsonify(response_data), 200



@app.route('/submit_invoice', methods=['POST'])
@jwt_required()  # This decorator ensures that a valid JWT token is required for access
def submit_invoice():
    data = request.get_json()

    user_id = get_jwt_identity()  # Get the user ID from the JWT token
    invoice_id = data.get('invoice_id')
    total_amount = data.get('total_amount')
    due_date_str = data.get('due_date')
    buyer_id = data.get('buyer_id')
    pdf_url = data.get('pdf_url')
    buyer_metamask_address = data.get('buyer_metamask_address')

    # Adding logging statements
    logging.info(f"Received invoice submission request from user {user_id}")

    if not (invoice_id and total_amount and due_date_str and pdf_url and buyer_id and buyer_metamask_address):
        logging.error("Missing required fields in the invoice submission request")
        return jsonify({'error': 'Missing required fields'}), 400

    try:
        due_date = datetime.strptime(due_date_str, '%d-%m-%Y').date()  # Update the format here
    except ValueError:
        logging.error("Invalid due_date format in the invoice submission request. Use dd-mm-yyyy.")
        return jsonify({'error': 'Invalid due_date format. Use dd-mm-yyyy.'}), 400

    # Fetch the corresponding User instance
    user = User.query.get(user_id)

    new_invoice = Invoice(
        user=user,
        invoice_id=invoice_id,
        total_amount=total_amount,
        due_date=due_date,
        buyer_id=buyer_id,
        pdf_url=pdf_url,
        buyer_metamask_address=buyer_metamask_address 
    )

    try:
        db.session.add(new_invoice)
        db.session.commit()

        # Check if the buyer is a 'Buyer' by role and update their BuyerDetails
        buyer = User.query.get(buyer_id)
        if buyer and buyer.role == UserRole.BUYER:
            buyer_details = BuyerDetails.query.filter_by(user_id=buyer_id).first()
            if buyer_details:
                buyer_details.update_total_balance()
            else:
                # Create BuyerDetails if not exist
                new_buyer_details = BuyerDetails(user_id=buyer_id, total_balance=total_amount)
                db.session.add(new_buyer_details)
            db.session.commit()

        # Audit logging for successful invoice submission
        log_entry = AuditLog(user_id=user_id, action=f"Invoice submitted: {invoice_id}")
        db.session.add(log_entry)
        db.session.commit()

        logging.info(f"Invoice {invoice_id} submitted successfully by user {user_id}")
        return jsonify({'message': 'Invoice submitted successfully!'}), 201
    except Exception as e:
        logging.error(f"Error while submitting invoice {invoice_id}: {str(e)}")
        db.session.rollback()
        return jsonify({'error': 'Internal server error'}), 500


@app.route('/uploads/<filename>', methods=['GET'])
@jwt_required()  # This decorator ensures that a valid JWT token is required for access
def uploaded_pdf(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)


@app.route('/biz-invoices', methods=['GET'])
def get_invoices():
    invoices = Invoice.query.all()
    invoice_list = [{
        'id': invoice.id,
        'user_id': invoice.user_id,
        'invoice_id': invoice.invoice_id,
        'total_amount': invoice.total_amount,
        'due_date': invoice.due_date.isoformat() if invoice.due_date else None,
        'buyer_id': invoice.buyer_id,
        'buyer_metamask_address': invoice.buyer_metamask_address,
        'pdf_url': invoice.pdf_url,
        'approval_status': invoice.approval_status,
        'metamask_address': invoice.metamask_address,
        'buyer_details_id': invoice.buyer_details_id,
        'status': invoice.status.name if invoice.status else None,  # Assuming InvoiceStatus is an Enum
    } for invoice in invoices]
    return jsonify(invoice_list)



@app.route('/approved_invoices', methods=['GET'])
@jwt_required()
def approved_invoices():
    user_id = get_jwt_identity()

    invoices = Invoice.query.filter(Invoice.user_id == user_id).all()

    invoice_data = []
    for invoice in invoices:
        approval_status = 'Approved' if invoice.approval_status else 'Approval Pending'
        invoice_list = {
            'id': invoice.id,
            'invoice_id': invoice.invoice_id,
            'total_amount': invoice.total_amount,
            'due_date': invoice.due_date,
            'buyer_id': invoice.buyer_id,
            'pdf_url': invoice.pdf_url,
            'approval_status': approval_status,
            'buyer_metamask_address': invoice.buyer_metamask_address 
        }
        invoice_data.append(invoice_list)

        # Moved inside the loop, logging each approved invoice
        if invoice.approval_status:
            log_entry = AuditLog(user_id=user_id, action=f"Invoice approved: {invoice.invoice_id}")
            db.session.add(log_entry)
    
    logging.info(f"User {user_id} fetched approved invoices.")
    return jsonify(invoice_data), 200

# ...

@app.route('/pending_approval_invoices', methods=['GET'])
@jwt_required()
def pending_approval_invoices():
    user_id = get_jwt_identity()

    invoices = Invoice.query.filter(Invoice.user_id == user_id).all()

    invoice_data = []
    for invoice in invoices:
        approval_status = 'Approved' if invoice.approval_status else 'Approval Pending'
        if not invoice.approval_status:
            invoice_list = {
                'id': invoice.id,
                'invoice_id': invoice.invoice_id,
                'total_amount': invoice.total_amount,
                'due_date': invoice.due_date.strftime('%Y-%m-%d'),
                'buyer_id': invoice.buyer_id,
                'pdf_url': invoice.pdf_url,
                'approval_status': approval_status,
                'buyer_metamask_address': invoice.buyer_metamask_address 
            }
            invoice_data.append(invoice_list)

    logging.info(f"User {user_id} fetched pending approval invoices.")
    return jsonify(invoice_data), 200

# ...

@app.route('/invoices/<int:invoice_id>', methods=['DELETE'])
@jwt_required()
def delete_invoice(invoice_id):
    invoice_to_delete = Invoice.query.get(invoice_id)

    if invoice_to_delete:
        pdf_url = invoice_to_delete.pdf_url
        if pdf_url:
            pdf_path = os.path.join(app.config['UPLOAD_FOLDER'], os.path.basename(pdf_url))
            try:
                if os.path.exists(pdf_path):
                    os.remove(pdf_path)
                    logging.info(f"Deleted PDF file: {pdf_path}")
                else:
                    logging.warning(f"PDF file not found: {pdf_path}")
            except Exception as e:
                logging.error(f"Error while deleting PDF file: {pdf_path}, {e}")

        db.session.delete(invoice_to_delete)
        db.session.commit()

        logging.info(f"Invoice with ID {invoice_id} and its associated PDF have been deleted.")
        return jsonify({"message": f"Invoice with ID {invoice_id} and its associated PDF have been deleted."}), 200
    else:
        logging.warning(f"Invoice with ID {invoice_id} not found.")
        return jsonify({"error": "Invoice not found."}), 404

# ...

@app.route('/invoices/pending_approval_pdfs/<int:invoice_id>', methods=['POST'])
@jwt_required()
def send_for_approval(invoice_id):
    invoice = Invoice.query.get(invoice_id)

    if invoice is None:
        logging.error(f"Invoice with ID {invoice_id} not found.")
        return jsonify({'error': 'Invoice not found.'}), 404

    user_id = get_jwt_identity()
    buyer_id = invoice.buyer_id
    buyer_metamask_address = invoice.buyer_metamask_address

    if user_id != invoice.user_id:
        logging.error(f"User {user_id} does not have permission to send this invoice for approval.")
        return jsonify({'error': 'You do not have permission to send this invoice for approval.'}), 403

    sent_for_approval = SentForApproval(
        invoice=invoice.id,
        user_id=user_id,
        buyer_id=buyer_id,
        buyer_metamask_address=buyer_metamask_address
    )

    db.session.add(sent_for_approval)
    db.session.commit()

    # Audit logging for sending invoice for approval
    log_entry = AuditLog(user_id=user_id, action=f"Invoice sent for approval: {invoice_id}")
    db.session.add(log_entry)
    db.session.commit()


    logging.info(f"Invoice with ID {invoice_id} sent for approval successfully by user {user_id}.")
    return jsonify({'message': 'Sent for approval successfully.'}), 200
# ...

@app.route('/came_for_approval', methods=['GET'])
@jwt_required()
def came_for_approval():
    user_id = get_jwt_identity()
    sent_for_approval_records = SentForApproval.query.filter(SentForApproval.buyer_id == user_id).all()

    invoices_data = []
    for sent_for_approval_record in sent_for_approval_records:
        if not sent_for_approval_record.approve_status:
            invoices = Invoice.query.filter(Invoice.approval_status == False).all()
            if invoices:
                invoices_data = [{
                'id': invoice.id,
                'mezzpro_id': invoice.user_id,  # Assuming this represents the Mezzpro ID
                'invoice_id': invoice.invoice_id,
                'total_amount': invoice.total_amount,
                'due_date': invoice.due_date.isoformat(),
                'seller_details': invoice.seller_id,  # Assuming you have a seller ID or similar
                'approval_status': invoice.approval_status,
                'payment_status': 'Paid' if invoice.payment_status else 'Unpaid'  # Assuming you have a payment status
            } for invoice in invoices]
            invoices_data.append(invoices_data)

    logging.info(f"User {user_id} fetched invoices that came for approval.")
    return jsonify(invoices_data)
# ...

@app.route('/approve_invoice/<int:invoice_id>', methods=['POST'])
@jwt_required()
def approve_invoice(invoice_id):
    current_user_id = get_jwt_identity()
    invoice = Invoice.query.get(invoice_id)
    
    if not invoice:
        return jsonify({"error": "Invoice not found"}), 404
    
    if not user_can_approve_invoice(current_user_id, invoice):
        return jsonify({"error": "You do not have permission to approve this invoice"}), 403
    
    invoice.approved_lender_id = current_user_id
    invoice.status = InvoiceStatus.APPROVED
    db.session.commit()
    
    return jsonify({"message": "Invoice approved successfully"}), 200

def user_can_approve_invoice(user_id, invoice):
    # Example implementation. Adjust according to your application's requirements.
    
    # Fetch the current user
    user = User.query.get(user_id)
    
    # Ensure the user is a lender
    if user.role != UserRole.LENDER_ADMIN:
        return False
    
    # Example check: ensure the invoice's buyer is among the users approved by the lender
    # This requires a relationship or logic to link lenders to their buyers
    approved_buyers = [buyer_detail.user_id for buyer_detail in BuyerDetails.query.filter_by(lender_id=user_id).all()]
    if invoice.buyer_id not in approved_buyers:
        return False
    
    return True


@app.route('/buyer_details/<int:buyer_id>', methods=['GET'])
@jwt_required()
def get_buyer_details(buyer_id):
    # Assuming you have a role check here to ensure only lenders can access this information

    buyer_details = BuyerDetails.query.filter_by(user_id=buyer_id).first()
    if not buyer_details:
        return jsonify({'error': 'Buyer not found'}), 404

    detailed_info = buyer_details.get_detailed_info()
    return jsonify(detailed_info), 200




# Route to list all buyers for approval
@app.route('/lender/list_buyers', methods=['GET'])
@jwt_required()
def list_buyers_for_approval():
    try:
        # Query for all buyers in the BuyerDetails table
        buyers = BuyerDetails.query.all()

        # Create a list of dictionaries containing buyer details
        buyers_list = [
            {
                'buyer_id': buyer.user_id,
                'total_balance': buyer.total_balance,
                'buyer_category': buyer.buyer_category,
                'funded_amount': buyer.funded_amount,
                'funding_status': buyer.funding_status,
                'detailed_info': buyer.get_detailed_info()
            }
            for buyer in buyers
        ]

        return jsonify(buyers_list), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500


#============LENDER APPROVAL====================

@app.route('/lender/approve_buyer/<int:buyer_id>', methods=['POST'])
@jwt_required()
def approve_buyer(buyer_id):
    lender_id = get_jwt_identity()
    data = request.get_json()
    funded_amount = float(data.get('funded_amount', 0.0))  # Convert to float

    # Retrieve escrow accounts for both lender and buyer
    lender_escrow = EscrowAccount.query.filter_by(user_id=lender_id).first()
    buyer_escrow = EscrowAccount.query.filter_by(user_id=buyer_id).first()

    if not lender_escrow or not buyer_escrow:
        return jsonify({'error': 'Escrow account not found'}), 404

    # Check if lender has sufficient funds
    if lender_escrow.balance < funded_amount:
        return jsonify({'error': 'Insufficient funds'}), 400

    # Create transaction record
    transaction = Transaction(sender_id=lender_escrow.id, receiver_id=buyer_escrow.id, amount=funded_amount, status='completed')
    db.session.add(transaction)

    # Update escrow balances
    lender_escrow.balance -= funded_amount
    buyer_escrow.balance += funded_amount

    # Update buyer details
    buyer_details = BuyerDetails.query.filter_by(user_id=buyer_id).first()
    if buyer_details:
        buyer_details.buyer_category = 'Approved'
        buyer_details.lender_id = lender_id
        buyer_details.funded_amount = funded_amount
        buyer_details.funding_status = 'Funded'
    else:
        return jsonify({'error': 'Buyer details not found'}), 404

    db.session.commit()
    return jsonify({'message': f'Buyer {buyer_id} approved successfully with funding amount {funded_amount}'}), 200

# @app.route('/lender/approve_buyer/<int:buyer_id>', methods=['POST'])
# @jwt_required()
# def approve_buyer(buyer_id):
#     lender_id = get_jwt_identity()

#     # Check if the buyer is already approved
#     buyer_details = BuyerDetails.query.filter_by(user_id=buyer_id).first()
#     if not buyer_details:
#         return jsonify({'error': 'Buyer details not found'}), 404

#     # Approve the buyer
#     buyer_details.buyer_category = 'Approved'
#     buyer_details.lender_id = lender_id
#     db.session.commit()

#     return jsonify({'message': f'Buyer {buyer_id} approved successfully'}), 200

# #=============LENDER FUNDING INVOICE==============

# @app.route('/lender/fund_invoice/<int:invoice_id>', methods=['POST'])
# @jwt_required()
# def fund_invoice(invoice_id):
#     lender_id = get_jwt_identity()
#     invoice = Invoice.query.get(invoice_id)

#     # Check if the invoice exists
#     if not invoice:
#         return jsonify({'error': 'Invoice does not exist'}), 404
    
#     # # Ensure the invoice is approved
#     # if not invoice.approval_status:
#     #     return jsonify({'error': 'Invoice is not approved'}), 400
    
#     # Verify the lender has approved the buyer related to this invoice
#     approved_buyer = BuyerDetails.query.filter_by(user_id=invoice.buyer_id, lender_id=lender_id).first()
#     if not approved_buyer:
#         return jsonify({'error': 'This buyer is not approved by you'}), 403

#     # Perform fund transfer
#     amount = invoice.total_amount
#     lender_escrow = EscrowAccount.query.filter_by(user_id=lender_id).first()
#     buyer_escrow = EscrowAccount.query.filter_by(user_id=invoice.buyer_id).first()

#     if lender_escrow.balance < amount:
#         return jsonify({'error': 'Insufficient funds in lender escrow'}), 400

#     lender_escrow.balance -= amount
#     buyer_escrow.balance += amount
#     invoice.status = InvoiceStatus.FUNDED
#     db.session.commit()

#     return jsonify({'message': f'Invoice {invoice_id} funded successfully'}), 200
@app.route('/settle_to_bank', methods=['POST'])
@jwt_required()
def settle_to_bank():
    user_id = get_jwt_identity()
    data = request.get_json()
    settlement_amount = data.get('settlement_amount')

    if settlement_amount is None:
        return jsonify({'error': 'Settlement amount is required'}), 400

    try:
        settlement_amount = float(settlement_amount)
    except ValueError:
        return jsonify({'error': 'Invalid settlement amount'}), 400

    # Retrieve the user's escrow account and user record
    escrow_account = EscrowAccount.query.filter_by(user_id=user_id).first()
    user = User.query.get(user_id)

    if escrow_account is None or user is None:
        return jsonify({'error': 'User or escrow account not found'}), 404

    if escrow_account.balance < settlement_amount:
        return jsonify({'error': 'Insufficient funds in escrow account'}), 400

    # Perform the settlement
    escrow_account.balance -= settlement_amount
    user.bank_balance += settlement_amount

    # Log the transaction
    transaction = Transaction(sender_id=escrow_account.id, receiver_id=user.id, amount=settlement_amount, status='completed')
    db.session.add(transaction)

    db.session.commit()

    return jsonify({'message': 'Settlement completed successfully', 'new_escrow_balance': escrow_account.balance, 'new_bank_balance': user.bank_balance}), 200


@app.route('/get_balances', methods=['GET'])
@jwt_required()
def get_balances():
    user_id = get_jwt_identity()
    
    user = User.query.get(user_id)
    escrow_account = EscrowAccount.query.filter_by(user_id=user_id).first()

    if user is None or escrow_account is None:
        return jsonify({'error': 'User or escrow account not found'}), 404

    return jsonify({
        'escrow_balance': escrow_account.balance,
        'bank_balance': user.bank_balance
    }), 200




@app.route('/request_early_payment', methods=['POST'])
@jwt_required()
def request_early_payment():
    user_id = get_jwt_identity()
    data = request.get_json()
    invoice_id = data.get('invoice_id')

    invoice = Invoice.query.get(invoice_id)
    if invoice is None:
        return jsonify({'error': 'Invoice not found'}), 404

    if invoice.user_id != user_id:
        return jsonify({'error': 'Unauthorized'}), 403

    # Check if the invoice is approved but not completed or tokenized
    if invoice.status != InvoiceStatus.APPROVED:
        return jsonify({'error': 'Invoice not in approved status or already processed'}), 400

    buyer_escrow = EscrowAccount.query.filter_by(user_id=invoice.buyer_id).first()
    seller_escrow = EscrowAccount.query.filter_by(user_id=user_id).first()

    if buyer_escrow.balance < invoice.total_amount:
        return jsonify({'error': 'Insufficient funds in buyer\'s escrow'}), 400

    # Proceed with early payment process
    transaction = Transaction(sender_id=buyer_escrow.id, receiver_id=seller_escrow.id, amount=invoice.total_amount, status='pending')
    db.session.add(transaction)

    buyer_escrow.balance -= invoice.total_amount
    seller_escrow.balance += invoice.total_amount
    invoice.status = InvoiceStatus.EARLY_PAYMENT  # Update the status to EARLY_PAYMENT

    db.session.commit()
    return jsonify({'message': 'Early payment requested successfully'}), 200


@app.route('/settle_payment/<int:transaction_id>', methods=['POST'])
@jwt_required()
def settle_payment(transaction_id):
    transaction = Transaction.query.get(transaction_id)
    if transaction.status != 'pending':
        return jsonify({'error': 'Invalid transaction status'}), 400

    # Retrieve the invoice related to this transaction
    invoice = Invoice.query.filter_by(id=transaction.invoice_id).first()
    if not invoice:
        return jsonify({'error': 'Invoice not found'}), 404

    seller = User.query.get(transaction.receiver.user_id)
    if seller.escrow_account.balance < transaction.amount:
        return jsonify({'error': 'Insufficient funds in escrow'}), 400

    seller.escrow_account.balance -= transaction.amount
    seller.bank_balance += transaction.amount
    transaction.status = 'completed'
    invoice.status = InvoiceStatus.COMPLETED  # Update invoice status to COMPLETED

    db.session.commit()
    return jsonify({ 
        'message': 'Payment settled successfully',
        'bank_balance': seller.bank_balance
    }), 200



# Set up logging
logging.basicConfig(level=logging.DEBUG)

@app.route('/get_transaction_details', methods=['GET'])
@jwt_required()
def get_transaction_details():
    user_id = get_jwt_identity()
    logging.debug(f"Received GET request to '/get_transaction_details' from user ID {user_id}")

    # Fetch escrow account of the user
    escrow_account = EscrowAccount.query.filter_by(user_id=user_id).first()

    if escrow_account is None:
        logging.warning(f"Escrow account not found for user ID {user_id}")
        return jsonify({'error': 'Escrow account not found'}), 404

    # Fetch sent and received transactions
    sent_transactions = [
        {
            'transaction_id': transaction.id,
            'receiver_id': transaction.receiver_id,
            'amount': transaction.amount,
            'transaction_date': transaction.transaction_date,
            'status': transaction.status,
        }
        for transaction in escrow_account.sent_transactions
    ]

    received_transactions = [
        {
            'transaction_id': transaction.id,
            'sender_id': transaction.sender_id,
            'amount': transaction.amount,
            'transaction_date': transaction.transaction_date,
            'status': transaction.status,
        }
        for transaction in escrow_account.received_transactions
    ]

    response_data = {'sent_transactions': sent_transactions, 'received_transactions': received_transactions}
    logging.debug(f"Returning response: {response_data}")

    return jsonify(response_data), 200


@app.route('/escrow/get_account', methods=['GET'])
def get_escrow_account():
    current_user_id = get_jwt_identity()
    escrow_account = EscrowAccount.query.filter_by(user_id=current_user_id).first()

    if escrow_account:
        # Serialize your escrow account data
        escrow_account_data = {
            'id': escrow_account.id,
            'balance': escrow_account.balance,
            'bank_name': escrow_account.bank_name,
            'account_number': escrow_account.account_number
        }
        return jsonify(escrow_account_data), 200
    else:
        return jsonify({'message': 'Escrow account not found'}), 404




@app.route('/tokens', methods=['GET'])
@jwt_required()  # This decorator ensures that a valid JWT token is required for access
def tokens():
    user_id = get_jwt_identity()

    # Check if the user (seller) has an approved invoice with the corresponding buyer ID
    approved_invoice = Invoice.query.filter_by(user_id=user_id, approval_status=True).first()

    if approved_invoice:
        # Allow the seller to access the tokens page
        return jsonify({'message': 'You can access the tokens page now.'}), 200
    else:
        # Deny access and show an error message
        return jsonify({'error': 'Invoice not approved by buyer. Access denied.'}), 403




# @app.route('/fetch_invoice_data', methods=['GET'])
# @jwt_required()  # This decorator ensures that a valid JWT token is required for access
# def fetch_invoice_data():
#     user_id = get_jwt_identity()
#     invoice_id = request.args.get('invoice_id')  # Get the invoice_id from the query parameter

#     logger.info(f"Fetching invoice data for invoice_id: {invoice_id} by user_id: {user_id}")

#     invoice = Invoice.query.filter_by(user_id=user_id, invoice_id=invoice_id).first()

#     if invoice:
#         # Convert the due_date to "dd-mm-yyyy" format
#         due_date = invoice.due_date.strftime("%d-%m-%Y")

#         invoice_data = {
#             'id': invoice.id,
#             'invoice_id': invoice.invoice_id,
#             'total_amount': invoice.total_amount,
#             'due_date': due_date,  # Convert Date to "dd-mm-yyyy" format
#             'buyer_id': invoice.buyer_id,
#             'pdf_url': invoice.pdf_url,
#             'approval_status': 'Approved' if invoice.approval_status else 'Approval Pending',
#             'buyer_metamask_address': invoice.buyer_metamask_address
#         }
#         logger.info(f"Successfully fetched invoice data for invoice_id: {invoice_id}")
#         return jsonify(invoice_data), 200
#     else:
#         logger.warning(f"Invoice not found for invoice_id: {invoice_id}")
#         return jsonify({'message': 'Invoice not found'}), 404

@app.route('/fetch_invoice_data', methods=['GET'])
@jwt_required()  # This decorator ensures that a valid JWT token is required for access
def fetch_invoice_data():
    user_id = get_jwt_identity()
    invoice_id = request.args.get('invoice_id')  # Get the invoice_id from the query parameter

    logger.info(f"Fetching invoice data for invoice_id: {invoice_id} by user_id: {user_id}")

    invoice = Invoice.query.filter_by(user_id=user_id, invoice_id=invoice_id).first()

    if invoice:
        invoice_data = {
            'id': invoice.id,
            'invoice_id': invoice.invoice_id,
            'total_amount': invoice.total_amount,
            'due_date': invoice.due_date.strftime("%Y-%m-%d"),  # Convert Date to "yyyy-mm-dd" format
            'buyer_id': invoice.buyer_id,
            'pdf_url': invoice.pdf_url,
            'approval_status': 'Approved' if invoice.approval_status else 'Approval Pending',
            'buyer_metamask_address': invoice.buyer_metamask_address
        }
        logger.info(f"Successfully fetched invoice data for invoice_id: {invoice_id}")
        return jsonify(invoice_data), 200
    else:
        logger.warning(f"Invoice not found for invoice_id: {invoice_id}")
        return jsonify({'message': 'Invoice not found'}), 404

@app.route('/validate_mint_tokens', methods=['POST'])
@jwt_required()
def validate_mint_tokens():
    data = request.get_json()
    invoice_amount = data.get('invoice_amount')  # Replace with the correct field name from your frontend
    requested_tokens = data.get('requested_tokens')  # Replace with the correct field name from your frontend

    logger.info(f"Validating mint tokens with invoice_amount: {invoice_amount}, requested_tokens: {requested_tokens}")

    if invoice_amount is None or requested_tokens is None:
        logger.warning("Missing required fields in mint token validation")
        return jsonify({'valid': False, 'message': 'Missing required fields'}), 400

    if requested_tokens > invoice_amount:
        logger.warning("Requested tokens exceed invoice amount in mint token validation")
        return jsonify({'valid': False, 'message': 'Requested tokens exceed invoice amount'}), 200
    else:
        logger.info("Token minting is valid")
        return jsonify({'valid': True, 'message': 'Token minting is valid'}), 200




if __name__ == "__main__":
    app.run(host='0.0.0.0', debug=True)