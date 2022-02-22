from flask import Flask, request, jsonify, make_response
from flask_sqlalchemy import SQLAlchemy
import uuid
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
from datetime import datetime, timedelta
from functools import wraps

app = Flask(__name__)

app.config['SECRET_KEY'] = 'test_metter_most'
app.config['SECRET_KEY'] = 'test_metter_most'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///mettermost.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = True
db = SQLAlchemy(app)


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    public_id = db.Column(db.String(50), unique=True)
    name = db.Column(db.String(100))
    email = db.Column(db.String(70), unique=True)
    password = db.Column(db.String(80))
    role = db.Column(db.String(80))

    def serialize(self):
        return {
            "id": self.id,
            "public_id": self.public_id,
            "name": self.name,
            "email":self.email,
            "role": self.role
        }


with app.app_context():
    db.create_all()


def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        print(f)
        if 'x-access-token' in request.headers:
            token = request.headers['x-access-token']

        if not token:
            return jsonify({'message': 'Token is missing !!'}), 401

        try:
            data = jwt.decode(token, app.config['SECRET_KEY'])
            current_user = User.query.filter_by(public_id=data['public_id']).first()
        except:
            return jsonify({'message': 'Token is invalid'}), 401

        return f(current_user, *args, **kwargs)

    return decorated


def is_admin(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        if 'x-access-token' in request.headers:
            token = request.headers['x-access-token']

        if not token:
            return jsonify({'message': 'Token is missing !!'}), 401

        try:
            data = jwt.decode(token, app.config['SECRET_KEY'])
            current_user = User.query.filter_by(public_id=data['public_id']).first()
            if current_user.role !='ADMIN':
                return jsonify({'message': 'invalid user role'}), 401

        except:
            return jsonify({'message': 'Token is invalid'}), 401

        return f(current_user, *args, **kwargs)

    return decorated

def is_agent(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        if 'x-access-token' in request.headers:
            token = request.headers['x-access-token']

        if not token:
            return jsonify({'message': 'Token is missing !!'}), 401

        try:
            data = jwt.decode(token, app.config['SECRET_KEY'])
            current_user = User.query.filter_by(public_id=data['public_id']).first()
            if current_user.role !='AGENT':
                return jsonify({'message': 'invalid user role'}), 401

        except:
            return jsonify({'message': 'Token is invalid'}), 401

        return f(current_user, *args, **kwargs)

    return decorated

def is_supervisor(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        if 'x-access-token' in request.headers:
            token = request.headers['x-access-token']

        if not token:
            return jsonify({'message': 'Token is missing !!'}), 401

        try:
            data = jwt.decode(token, app.config['SECRET_KEY'])
            current_user = User.query.filter_by(public_id=data['public_id']).first()
            if current_user.role !='SUPERVISOR':
                return jsonify({'message': 'invalid user role'}), 401

        except:
            return jsonify({'message': 'Token is invalid'}), 401

        return f(current_user, *args, **kwargs)

    return decorated


@app.route('/api/v1/', methods=['GET'])
def index():
    return jsonify({'home': ' user home'})


@app.route('/api/v1/life', methods=['GET'])
@token_required
@is_admin
def moduleOneLife(current_user):
    return jsonify({'home': ' user moduleOneLife'})


@app.route('/api/v1/bank', methods=['GET'])
@token_required
@is_agent
def moduleTwoBank(current_user):
    return jsonify({'home': ' user moduleTwoBank'})

@app.route('/api/v1/home', methods=['GET'])
@token_required
@is_supervisor
def moduleTwoHome(current_user):
    return jsonify({'home': ' user moduleTwoHome'})



@app.route('/api/v1/user', methods=['GET'])
@token_required
def get_all_users(current_user):
    users = User.query.all()
    output = []
    for user in users:
        output.append({
            'public_id': user.public_id,
            'name': user.name,
            'email': user.email
        })

    return jsonify({'users': output})


@app.route('/api/v1/login', methods=['POST'])
def login():
    auth = request.json

    if not auth or not auth['email'] or not auth['password']:
        return make_response(
            'Could not verify',
            401,
            {'WWW-Authenticate': 'Basic realm ="Login required !!"'}
        )

    user = User.query.filter_by(email=auth['email']).first()

    if not user:
        return make_response(
            'Could not verify',
            401,
            {'WWW-Authenticate': 'Basic realm ="User does not exist !!"'}
        )

    if check_password_hash(user.password, auth['password']):
        token = jwt.encode({
            'public_id': user.public_id,
            'exp': datetime.utcnow() + timedelta(minutes=30)
        }, app.config['SECRET_KEY'])

        return make_response(jsonify({"user": user.serialize(), 'token': token.decode('UTF-8')}), 201)

    return make_response(
        'Could not verify',
        403,
        {'WWW-Authenticate': 'Basic realm ="Wrong Password !!"'}
    )


@app.route('/api/v1/signup', methods=['POST'])
def signup():
    data = request.json

    name, email, role = data['name'], data['email'], data['role']
    password = data['password']
    user = User.query.filter_by(email=email).first()

    if not user:
        user = User(public_id=str(uuid.uuid4()), name=name, email=email, password=generate_password_hash(password),
                    role=role)
        db.session.add(user)
        db.session.commit()
        return make_response('Successfully registered.', 201)
    else:
        return make_response('User already exists. Please Log in.', 202)


if __name__ == '__main__':
    print('welcome to matter most')
    app.run()
