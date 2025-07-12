# StackIt MongoDB Version - Full index.py with all required routes

from flask import Flask, request, jsonify, g
from flask_cors import CORS
from pymongo import MongoClient, ASCENDING, DESCENDING
from bson.objectid import ObjectId
from datetime import datetime, timedelta
import bcrypt, jwt, os, re
from functools import wraps

# ========== CONFIGURATION ==========
app = Flask(__name__)
CORS(app)

app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'your-secret-key')
app.config['MONGO_URI'] = os.getenv('MONGO_URI', 'mongodb+srv://itssubi76:zaid0504@zaidcluster.ds3grvk.mongodb.net/?retryWrites=true&w=majority&appName=zaidCluster')
client = MongoClient(app.config['MONGO_URI'])
db = client['stackit']

# ========== COLLECTION REFERENCES ==========
users = db.users
tags = db.tags
questions = db.questions
answers = db.answers
votes = db.votes
question_tags = db.question_tags
notifications = db.notifications
user_sessions = db.user_sessions
activity_logs = db.activity_logs
user_preferences = db.user_preferences

# ========== AUTH DECORATORS ==========
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization')
        if not token:
            return jsonify({'error': 'Missing token'}), 401
        try:
            token = token.replace('Bearer ', '')
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
            user = users.find_one({'_id': ObjectId(data['user_id']), 'is_active': True})
            if not user:
                return jsonify({'error': 'Invalid user'}), 401
            g.current_user = user
        except jwt.ExpiredSignatureError:
            return jsonify({'error': 'Token expired'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'error': 'Invalid token'}), 401
        return f(*args, **kwargs)
    return decorated

def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if g.current_user.get('role') != 'admin':
            return jsonify({'error': 'Admin privileges required'}), 403
        return f(*args, **kwargs)
    return decorated

# ========== UTILITIES ==========
def validate_email(email):
    return re.match(r'^[\w\.-]+@[\w\.-]+\.\w+$', email)

def validate_password(password):
    return (
        len(password) >= 8 and
        re.search(r'[A-Z]', password) and
        re.search(r'[a-z]', password) and
        re.search(r'\d', password)
    )

# ========== INIT DB ==========
def initialize_collections():
    collections = [users, tags, questions, answers, votes, question_tags, notifications, user_sessions, activity_logs, user_preferences]
    for col in collections:
        col.create_index([('created_at', DESCENDING)])
    users.create_index("username", unique=True)
    users.create_index("email", unique=True)
    votes.create_index([("user_id", ASCENDING), ("votable_type", ASCENDING), ("votable_id", ASCENDING)], unique=True)
    tags.create_index("name", unique=True)

# ========== ROUTES ==========
@app.route('/api/auth/signup', methods=['POST'])
def signup():
    data = request.get_json()
    username, email, password = data.get('username'), data.get('email'), data.get('password')
    if not all([username, email, password]):
        return jsonify({'error': 'Missing fields'}), 400
    if not validate_email(email):
        return jsonify({'error': 'Invalid email'}), 400
    if not validate_password(password):
        return jsonify({'error': 'Weak password'}), 400
    if users.find_one({'$or': [{'username': username}, {'email': email}]}):
        return jsonify({'error': 'User already exists'}), 409

    hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
    user_doc = {
        'username': username, 'email': email, 'password_hash': hashed,
        'role': 'user', 'reputation': 0, 'is_active': True,
        'created_at': datetime.utcnow(), 'updated_at': datetime.utcnow(),
    }
    result = users.insert_one(user_doc)
    token = jwt.encode({'user_id': str(result.inserted_id), 'exp': datetime.utcnow() + timedelta(days=30)}, app.config['SECRET_KEY'], algorithm='HS256')
    return jsonify({'token': token}), 201

@app.route('/api/auth/login', methods=['POST'])
def login():
    data = request.get_json()
    login = data.get('login')
    password = data.get('password')
    user = users.find_one({'$or': [{'username': login}, {'email': login}]})
    if not user or not bcrypt.checkpw(password.encode(), user['password_hash']):
        return jsonify({'error': 'Invalid credentials'}), 401
    token = jwt.encode({'user_id': str(user['_id']), 'exp': datetime.utcnow() + timedelta(days=30)}, app.config['SECRET_KEY'], algorithm='HS256')
    return jsonify({'token': token}), 200

@app.route('/api/questions', methods=['POST'])
@token_required
def post_question():
    data = request.get_json()
    question = {
        'title': data.get('title'), 'description': data.get('description'),
        'author_id': g.current_user['_id'], 'views': 0, 'upvotes': 0, 'downvotes': 0,
        'score': 0, 'is_closed': False, 'created_at': datetime.utcnow(), 'last_activity': datetime.utcnow()
    }
    result = questions.insert_one(question)
    return jsonify({'question_id': str(result.inserted_id)}), 201

@app.route('/api/questions', methods=['GET'])
def get_all_questions():
    results = []
    for q in questions.find().sort("created_at", DESCENDING):
        author = users.find_one({'_id': q['author_id']})
        results.append({
            'id': str(q['_id']), 'title': q['title'], 'author': author['username'],
            'score': q['score'], 'views': q['views'], 'created_at': q['created_at']
        })
    return jsonify(results)

@app.route('/api/questions/<question_id>', methods=['GET'])
def view_question_with_answers(question_id):
    question = questions.find_one({'_id': ObjectId(question_id)})
    if not question:
        return jsonify({'error': 'Not found'}), 404
    author = users.find_one({'_id': question['author_id']})
    ans_list = list(answers.find({'question_id': ObjectId(question_id)}))
    ans_data = [{
        'id': str(a['_id']), 'content': a['content'], 'author_id': str(a['author_id']), 'score': a['score']
    } for a in ans_list]
    return jsonify({
        'id': str(question['_id']), 'title': question['title'], 'description': question['description'],
        'author': author['username'], 'score': question['score'], 'answers': ans_data
    })

@app.route('/api/questions/<question_id>/answers', methods=['POST'])
@token_required
def answer_question(question_id):
    data = request.get_json()
    answer = {
        'question_id': ObjectId(question_id), 'content': data['content'],
        'author_id': g.current_user['_id'], 'score': 0,
        'created_at': datetime.utcnow(), 'updated_at': datetime.utcnow()
    }
    result = answers.insert_one(answer)
    questions.update_one({'_id': ObjectId(question_id)}, {'$set': {'last_activity': datetime.utcnow()}})
    return jsonify({'answer_id': str(result.inserted_id)}), 201

@app.route('/api/vote', methods=['POST'])
@token_required
def vote():
    data = request.get_json()
    votable_type = data['votable_type']
    votable_id = ObjectId(data['votable_id'])
    vote_type = data['vote_type']
    if votable_type not in ['question', 'answer'] or vote_type not in ['upvote', 'downvote']:
        return jsonify({'error': 'Invalid vote'}), 400

    coll = questions if votable_type == 'question' else answers
    field = 'upvotes' if vote_type == 'upvote' else 'downvotes'
    update = {'$inc': {'score': 1 if vote_type == 'upvote' else -1, field: 1}}
    result = coll.update_one({'_id': votable_id}, update)
    if result.modified_count:
        votes.insert_one({
            'user_id': g.current_user['_id'], 'votable_type': votable_type,
            'votable_id': votable_id, 'vote_type': vote_type,
            'created_at': datetime.utcnow()
        })
        return jsonify({'success': True}), 200
    return jsonify({'error': 'Vote failed'}), 400

@app.route('/api/admin/questions/<question_id>/close', methods=['PATCH'])
@token_required
@admin_required
def admin_close_question(question_id):
    data = request.get_json()
    reason = data.get('reason', 'Closed by admin')
    result = questions.update_one({'_id': ObjectId(question_id)}, {'$set': {
        'is_closed': True, 'close_reason': reason, 'closed_at': datetime.utcnow()
    }})
    return jsonify({'closed': result.modified_count == 1})

@app.route('/api/health')
def health():
    return jsonify({'status': 'ok'})

if __name__ == '__main__':
    initialize_collections()
    app.run(debug=True)
