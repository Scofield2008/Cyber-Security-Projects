from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
from functools import wraps
from datetime import datetime, timedelta
import redis


# Config

class Config:
    SECRET_KEY = 'your_secret_key_here'
    SQLALCHEMY_DATABASE_URI = 'sqlite:///db.sqlite3'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    REDIS_HOST = 'localhost'
    REDIS_PORT = 6379
    RATE_LIMIT = 5       # max requests per RATE_PERIOD
    RATE_PERIOD = 60     # seconds window for rate limiting


# Setup Flask, DB, Redis

app = Flask(__name__)
app.config.from_object(Config)
db = SQLAlchemy(app)
r = redis.Redis(host=Config.REDIS_HOST, port=Config.REDIS_PORT, db=0, decode_responses=True)


# Models

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    role = db.Column(db.String(20), nullable=False, default='user')

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)


# Auth helpers

def generate_token(user):
    payload = {
        'user_id': user.id,
        'role': user.role,
        'exp': datetime.utcnow() + timedelta(hours=2)
    }
    return jwt.encode(payload, Config.SECRET_KEY, algorithm='HS256')

def decode_token(token):
    try:
        return jwt.decode(token, Config.SECRET_KEY, algorithms=['HS256'])
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        if 'Authorization' in request.headers:
            auth_header = request.headers['Authorization']
            if auth_header.startswith('Bearer '):
                token = auth_header[7:]  # Remove 'Bearer ' prefix

        if not token:
            return jsonify({'message': 'Token is missing'}), 401

        data = decode_token(token)
        if not data:
            return jsonify({'message': 'Token is invalid or expired'}), 401

        user = User.query.get(data['user_id'])
        if not user:
            return jsonify({'message': 'User not found'}), 404

        return f(user, *args, **kwargs)
    return decorated

def role_required(role):
    def decorator(f):
        @wraps(f)
        def wrapped(user, *args, **kwargs):
            if user.role != role:
                return jsonify({'message': 'Forbidden: Insufficient role'}), 403
            return f(user, *args, **kwargs)
        return wrapped
    return decorator


# IP Blocking and Rate Limiting

FAILED_ATTEMPTS_KEY = "failed_login_attempts:"
BLOCKED_IPS_KEY = "blocked_ips:"

def get_client_ip():
    if request.headers.get('X-Forwarded-For'):
        return request.headers.get('X-Forwarded-For').split(',')[0].strip()
    return request.remote_addr or 'unknown'

def check_and_block_ip(ip):
    if r.sismember(BLOCKED_IPS_KEY, ip):
        return True
    return False

def record_failed_login(ip):
    key = FAILED_ATTEMPTS_KEY + ip
    attempts = r.incr(key)
    if attempts == 1:
        r.expire(key, 300)  # fail attempts reset after 5 minutes
    if attempts > 5:
        r.sadd(BLOCKED_IPS_KEY, ip)
        r.expire(BLOCKED_IPS_KEY, 600)  # block IP for 10 minutes

def rate_limiter(f):
    @wraps(f)
    def decorated(user, *args, **kwargs):
        key = f"rate_limit:{user.id}"
        count = r.get(key)
        if count and int(count) >= Config.RATE_LIMIT:
            return jsonify({"message": "Rate limit exceeded"}), 429
        else:
            pipe = r.pipeline()
            pipe.incr(key, 1)
            pipe.expire(key, Config.RATE_PERIOD)
            pipe.execute()
        return f(user, *args, **kwargs)
    return decorated


# Routes

@app.route('/')
def index():
    return jsonify({"message": "Welcome to the Secure Loan API Gateway!"})

@app.route('/register', methods=['POST'])
def register():
    data = request.json
    if not data or not data.get('email') or not data.get('password'):
        return jsonify({"message": "Email and password required"}), 400

    if User.query.filter_by(email=data['email']).first():
        return jsonify({"message": "User already exists"}), 400

    user = User(email=data['email'], role=data.get('role', 'user'))
    user.set_password(data['password'])
    db.session.add(user)
    db.session.commit()
    return jsonify({"message": "User created"}), 201

@app.route('/login', methods=['POST'])
def login():
    data = request.json
    ip = get_client_ip()

    if check_and_block_ip(ip):
        return jsonify({"message": "Too many failed attempts. Try later."}), 403

    if not data or not data.get('email') or not data.get('password'):
        return jsonify({"message": "Email and password required"}), 400

    user = User.query.filter_by(email=data['email']).first()
    if not user or not user.check_password(data['password']):
        record_failed_login(ip)
        return jsonify({"message": "Invalid credentials"}), 401

    token = generate_token(user)
    return jsonify({"token": token})

@app.route('/loan-data', methods=['GET'])
@token_required
@rate_limiter
@role_required('admin')
def loan_data(user):
    return jsonify({"message": f"Loan data for admin {user.email}"}), 200

@app.route('/profile', methods=['GET'])
@token_required
@rate_limiter
def profile(user):
    return jsonify({
        "id": user.id,
        "email": user.email,
        "role": user.role
    })

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
