from flask import Flask, request, jsonify
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
import datetime
from functools import wraps
from flask_migrate import Migrate

app = Flask(__name__)
CORS(app)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SECRET_KEY'] = 'your_secret_key'
db = SQLAlchemy(app)
migrate = Migrate(app, db)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    histories = db.relationship('History', backref='user', lazy=True)

class History(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    prompt = db.Column(db.String(200), nullable=False)
    output = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.datetime.utcnow)
    updated_at = db.Column(db.DateTime, nullable=False, default=datetime.datetime.utcnow, onupdate=datetime.datetime.utcnow)

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization')
        if not token:
            return jsonify({'message': 'Token is missing!'}), 403
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
            current_user = User.query.filter_by(username=data['username']).first()
        except Exception as e:
            return jsonify({'message': 'Token is invalid!', 'error': str(e)}), 403
        return f(current_user, *args, **kwargs)
    return decorated

@app.route('/')
def home():
    return "Flask server is running!"

@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    hashed_password = generate_password_hash(data['password'], method='pbkdf2:sha256')
    new_user = User(username=data['username'], email=data['email'], password=hashed_password)
    db.session.add(new_user)
    db.session.commit()
    return jsonify({'message': 'registered successfully'})

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    user = User.query.filter_by(username=data['username']).first()
    if user and check_password_hash(user.password, data['password']):
        token = jwt.encode({
            'username': user.username,
            'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=30)
        }, app.config['SECRET_KEY'], algorithm='HS256')
        return jsonify({'message': 'login successful', 'token': token})
    return jsonify({'message': 'invalid credentials'}), 401

@app.route('/protected', methods=['GET'])
@token_required
def protected(current_user):
    return jsonify({'message': f'Hello, {current_user.username}! This is a protected route.'})

@app.route('/profile', methods=['GET'])
@token_required
def profile(current_user):
    return jsonify({'username': current_user.username, 'email': current_user.email})

@app.route('/history', methods=['POST'])
@token_required
def add_history(current_user):
    data = request.get_json()
    history_data = eval(data['history'])  # Pastikan data JSON dikonversi menjadi objek Python
    new_history = History(
        user_id=current_user.id,
        prompt=history_data['prompt'],
        output=history_data['output'].replace('**', ''),  # Remove ** from output
    )
    db.session.add(new_history)
    db.session.commit()
    return jsonify({'message': 'history added successfully'})

@app.route('/history', methods=['GET'])
@token_required
def get_history(current_user):
    histories = History.query.filter_by(user_id=current_user.id).all()
    output = []
    for history in histories:
        output.append({
            'id': history.id,
            'prompt': history.prompt,
            'output': history.output,
            'created_at': history.created_at,
            'updated_at': history.updated_at
        })
    return jsonify(output)

@app.route('/history/<int:history_id>', methods=['DELETE'])
@token_required
def delete_history(current_user, history_id):
    history = History.query.filter_by(id=history_id, user_id=current_user.id).first()
    if not history:
        return jsonify({'message': 'History not found'}), 404

    db.session.delete(history)
    db.session.commit()
    return jsonify({'message': 'History deleted successfully'})


if __name__ == '__main__':
    app.run(debug=True, port=5001)
