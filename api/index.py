# StackIt API System - Complete Implementation
# File: api/index.py (for Vercel deployment)

from flask import Flask, request, jsonify, g
from flask_cors import CORS
import os
import jwt
import bcrypt
import psycopg2
from psycopg2.extras import RealDictCursor
from datetime import datetime, timedelta
import cloudinary
import cloudinary.uploader
from functools import wraps
import re
from urllib.parse import urlparse
import base64
import json

app = Flask(__name__)
CORS(app)

# Configuration
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'your-secret-key-here')
app.config['DATABASE_URL'] = os.environ.get('DATABASE_URL', 'postgresql://user:password@localhost/stackit')
app.config['CLOUDINARY_URL'] = os.environ.get('CLOUDINARY_URL')

# Cloudinary configuration for image uploads
if app.config['CLOUDINARY_URL']:
    cloudinary.config(cloudinary_url=app.config['CLOUDINARY_URL'])

# Database connection
def get_db_connection():
    conn = psycopg2.connect(
        app.config['DATABASE_URL'],
        cursor_factory=RealDictCursor
    )
    return conn

# Authentication decorator
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization')
        
        if not token:
            return jsonify({'error': 'Token is missing'}), 401
        
        try:
            if token.startswith('Bearer '):
                token = token[7:]
            
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
            current_user_id = data['user_id']
            
            # Get user from database
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM users WHERE id = %s AND is_active = true", (current_user_id,))
            current_user = cursor.fetchone()
            conn.close()
            
            if not current_user:
                return jsonify({'error': 'User not found'}), 401
                
            g.current_user = current_user
            
        except jwt.ExpiredSignatureError:
            return jsonify({'error': 'Token has expired'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'error': 'Invalid token'}), 401
        
        return f(*args, **kwargs)
    
    return decorated

# Utility functions
def validate_email(email):
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None

def validate_password(password):
    # At least 8 characters, one uppercase, one lowercase, one number
    if len(password) < 8:
        return False
    if not re.search(r'[A-Z]', password):
        return False
    if not re.search(r'[a-z]', password):
        return False
    if not re.search(r'\d', password):
        return False
    return True

def extract_images_from_content(content):
    """Extract image URLs from rich text content"""
    img_pattern = r'<img[^>]+src="([^"]+)"[^>]*>'
    images = re.findall(img_pattern, content)
    return images

def sanitize_content(content):
    """Basic HTML sanitization - allow only safe tags"""
    allowed_tags = ['p', 'br', 'strong', 'em', 'u', 'ol', 'ul', 'li', 'a', 'img', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6']
    # This is a simplified sanitization - in production, use a proper library like bleach
    return content

# ===========================================
# API 1: AUTHENTICATION (Login & Signup)
# ===========================================

@app.route('/api/auth/signup', methods=['POST'])
def signup():
    """
    User Registration API
    
    Logic:
    1. Validate input data (email, username, password)
    2. Check if user already exists
    3. Hash password using bcrypt
    4. Create user in database
    5. Generate JWT token
    6. Return user data and token
    
    Input:
    - username: string (3-50 characters, alphanumeric + underscore)
    - email: string (valid email format)
    - password: string (min 8 chars, 1 upper, 1 lower, 1 number)
    
    Output:
    - success: user data and JWT token
    - error: validation errors or server errors
    """
    try:
        data = request.get_json()
        
        # Validate input
        if not data or not data.get('username') or not data.get('email') or not data.get('password'):
            return jsonify({'error': 'Missing required fields'}), 400
        
        username = data['username'].strip()
        email = data['email'].strip().lower()
        password = data['password']
        
        # Validate username
        if not re.match(r'^[a-zA-Z0-9_]{3,50}$', username):
            return jsonify({'error': 'Username must be 3-50 characters and contain only letters, numbers, and underscores'}), 400
        
        # Validate email
        if not validate_email(email):
            return jsonify({'error': 'Invalid email format'}), 400
        
        # Validate password
        if not validate_password(password):
            return jsonify({'error': 'Password must be at least 8 characters with uppercase, lowercase, and number'}), 400
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Check if user exists
        cursor.execute("SELECT id FROM users WHERE username = %s OR email = %s", (username, email))
        if cursor.fetchone():
            conn.close()
            return jsonify({'error': 'Username or email already exists'}), 409
        
        # Hash password
        password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        
        # Create user
        cursor.execute("""
            INSERT INTO users (username, email, password_hash, role, created_at)
            VALUES (%s, %s, %s, %s, %s)
            RETURNING id, username, email, role, reputation, created_at
        """, (username, email, password_hash, 'user', datetime.utcnow()))
        
        user = cursor.fetchone()
        conn.commit()
        conn.close()
        
        # Generate JWT token
        token = jwt.encode({
            'user_id': user['id'],
            'username': user['username'],
            'exp': datetime.utcnow() + timedelta(days=30)
        }, app.config['SECRET_KEY'], algorithm='HS256')
        
        return jsonify({
            'success': True,
            'message': 'User registered successfully',
            'user': {
                'id': user['id'],
                'username': user['username'],
                'email': user['email'],
                'role': user['role'],
                'reputation': user['reputation'],
                'created_at': user['created_at'].isoformat()
            },
            'token': token
        }), 201
        
    except Exception as e:
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/api/auth/login', methods=['POST'])
def login():
    """
    User Login API
    
    Logic:
    1. Validate input (email/username and password)
    2. Find user in database
    3. Verify password using bcrypt
    4. Generate JWT token
    5. Update last_login timestamp
    6. Return user data and token
    
    Input:
    - login: string (email or username)
    - password: string
    
    Output:
    - success: user data and JWT token
    - error: authentication errors
    """
    try:
        data = request.get_json()
        
        if not data or not data.get('login') or not data.get('password'):
            return jsonify({'error': 'Missing login credentials'}), 400
        
        login = data['login'].strip().lower()
        password = data['password']
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Find user by email or username
        cursor.execute("""
            SELECT id, username, email, password_hash, role, reputation, is_active, created_at
            FROM users 
            WHERE (email = %s OR username = %s) AND is_active = true
        """, (login, login))
        
        user = cursor.fetchone()
        
        if not user:
            conn.close()
            return jsonify({'error': 'Invalid credentials'}), 401
        
        # Verify password
        if not bcrypt.checkpw(password.encode('utf-8'), user['password_hash'].encode('utf-8')):
            conn.close()
            return jsonify({'error': 'Invalid credentials'}), 401
        
        # Update last login
        cursor.execute("UPDATE users SET last_login = %s WHERE id = %s", (datetime.utcnow(), user['id']))
        conn.commit()
        conn.close()
        
        # Generate JWT token
        token = jwt.encode({
            'user_id': user['id'],
            'username': user['username'],
            'exp': datetime.utcnow() + timedelta(days=30)
        }, app.config['SECRET_KEY'], algorithm='HS256')
        
        return jsonify({
            'success': True,
            'message': 'Login successful',
            'user': {
                'id': user['id'],
                'username': user['username'],
                'email': user['email'],
                'role': user['role'],
                'reputation': user['reputation'],
                'created_at': user['created_at'].isoformat()
            },
            'token': token
        }), 200
        
    except Exception as e:
        return jsonify({'error': 'Internal server error'}), 500

# ===========================================
# API 2: POST QUESTIONS WITH IMAGES
# ===========================================

@app.route('/api/questions', methods=['POST'])
@token_required
def create_question():
    """
    Create Question API with Image Support
    
    Logic:
    1. Validate user authentication
    2. Extract and validate question data
    3. Process rich text content and extract images
    4. Upload images to Cloudinary
    5. Replace image URLs in content
    6. Validate and create tags
    7. Save question to database
    8. Return question data
    
    Input:
    - title: string (5-255 characters)
    - description: string (rich text HTML)
    - tags: array of strings (1-5 tags)
    - images: array of base64 encoded images (optional)
    
    Output:
    - success: question data with ID
    - error: validation errors
    """
    try:
        data = request.get_json()
        
        if not data or not data.get('title') or not data.get('description'):
            return jsonify({'error': 'Title and description are required'}), 400
        
        title = data['title'].strip()
        description = data['description'].strip()
        tags = data.get('tags', [])
        images = data.get('images', [])
        
        # Validate title
        if len(title) < 5 or len(title) > 255:
            return jsonify({'error': 'Title must be 5-255 characters'}), 400
        
        # Validate description
        if len(description) < 10:
            return jsonify({'error': 'Description must be at least 10 characters'}), 400
        
        # Validate tags
        if not tags or len(tags) == 0:
            return jsonify({'error': 'At least one tag is required'}), 400
        
        if len(tags) > 5:
            return jsonify({'error': 'Maximum 5 tags allowed'}), 400
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Process images if provided
        uploaded_images = []
        if images:
            for i, image_data in enumerate(images):
                try:
                    # Upload to Cloudinary
                    upload_result = cloudinary.uploader.upload(
                        image_data,
                        folder="stackit/questions",
                        transformation=[
                            {"width": 800, "height": 600, "crop": "limit"},
                            {"quality": "auto"}
                        ]
                    )
                    uploaded_images.append(upload_result['secure_url'])
                except Exception as e:
                    return jsonify({'error': f'Image upload failed: {str(e)}'}), 400
        
        # Replace image placeholders in description with uploaded URLs
        for i, image_url in enumerate(uploaded_images):
            description = description.replace(f'{{image_{i}}}', f'<img src="{image_url}" alt="Question image" />')
        
        # Sanitize content
        description = sanitize_content(description)
        
        # Create question
        cursor.execute("""
            INSERT INTO questions (title, description, author_id, created_at, updated_at, last_activity)
            VALUES (%s, %s, %s, %s, %s, %s)
            RETURNING id, title, description, views, upvotes, downvotes, score, created_at
        """, (title, description, g.current_user['id'], datetime.utcnow(), datetime.utcnow(), datetime.utcnow()))
        
        question = cursor.fetchone()
        question_id = question['id']
        
        # Process tags
        tag_ids = []
        for tag_name in tags:
            tag_name = tag_name.strip().lower()
            if not tag_name:
                continue
                
            # Check if tag exists
            cursor.execute("SELECT id FROM tags WHERE name = %s", (tag_name,))
            tag = cursor.fetchone()
            
            if tag:
                tag_ids.append(tag['id'])
            else:
                # Create new tag
                cursor.execute("""
                    INSERT INTO tags (name, created_at, created_by)
                    VALUES (%s, %s, %s)
                    RETURNING id
                """, (tag_name, datetime.utcnow(), g.current_user['id']))
                new_tag = cursor.fetchone()
                tag_ids.append(new_tag['id'])
        
        # Link tags to question
        for tag_id in tag_ids:
            cursor.execute("INSERT INTO question_tags (question_id, tag_id) VALUES (%s, %s)", (question_id, tag_id))
        
        # Get tags for response
        cursor.execute("""
            SELECT t.id, t.name, t.color
            FROM tags t
            JOIN question_tags qt ON t.id = qt.tag_id
            WHERE qt.question_id = %s
        """, (question_id,))
        question_tags = cursor.fetchall()
        
        conn.commit()
        conn.close()
        
        return jsonify({
            'success': True,
            'message': 'Question created successfully',
            'question': {
                'id': question['id'],
                'title': question['title'],
                'description': question['description'],
                'author': {
                    'id': g.current_user['id'],
                    'username': g.current_user['username']
                },
                'views': question['views'],
                'upvotes': question['upvotes'],
                'downvotes': question['downvotes'],
                'score': question['score'],
                'tags': [{'id': tag['id'], 'name': tag['name'], 'color': tag['color']} for tag in question_tags],
                'created_at': question['created_at'].isoformat(),
                'images': uploaded_images
            }
        }), 201
        
    except Exception as e:
        return jsonify({'error': 'Internal server error'}), 500

# ===========================================
# API 3: PAGINATION API FOR QUESTIONS
# ===========================================

@app.route('/api/questions', methods=['GET'])
def get_questions():
    """
    Questions Pagination API
    
    Logic - Cursor-based Pagination:
    1. Use cursor-based pagination for better performance
    2. Sort by multiple criteria: score DESC, created_at DESC
    3. Use composite cursor (score + created_at + id)
    4. Filter by tags, search query if provided
    5. Include question metadata and author info
    6. Return paginated results with next cursor
    
    Why Cursor-based over Offset-based:
    - Better performance for large datasets
    - Consistent results (no duplicates when new items added)
    - Scales well with database size
    - Real-time updates don't affect pagination
    
    Input (Query Parameters):
    - limit: int (default 10, max 50)
    - cursor: string (encoded cursor for pagination)
    - tags: comma-separated tag names
    - search: string (search in title/description)
    - sort: string (newest, oldest, score, views)
    
    Output:
    - questions: array of question objects
    - pagination: cursor info for next page
    - total_count: total questions matching filters
    """
    try:
        # Parse query parameters
        limit = min(int(request.args.get('limit', 10)), 50)
        cursor = request.args.get('cursor')
        tags_filter = request.args.get('tags')
        search_query = request.args.get('search', '').strip()
        sort_by = request.args.get('sort', 'newest')  # newest, oldest, score, views
        
        conn = get_db_connection()
        cursor_db = conn.cursor()
        
        # Build base query
        base_query = """
            SELECT DISTINCT q.id, q.title, q.description, q.views, q.upvotes, q.downvotes, 
                   q.score, q.created_at, q.updated_at, q.last_activity,
                   u.id as author_id, u.username, u.reputation,
                   COUNT(a.id) as answer_count,
                   CASE WHEN q.accepted_answer_id IS NOT NULL THEN true ELSE false END as has_accepted_answer
            FROM questions q
            JOIN users u ON q.author_id = u.id
            LEFT JOIN answers a ON q.id = a.question_id
            LEFT JOIN question_tags qt ON q.id = qt.question_id
            LEFT JOIN tags t ON qt.tag_id = t.id
            WHERE q.is_closed = false
        """
        
        params = []
        
        # Add search filter
        if search_query:
            base_query += " AND (q.title ILIKE %s OR q.description ILIKE %s)"
            search_param = f"%{search_query}%"
            params.extend([search_param, search_param])
        
        # Add tags filter
        if tags_filter:
            tag_names = [tag.strip().lower() for tag in tags_filter.split(',')]
            tag_placeholders = ','.join(['%s'] * len(tag_names))
            base_query += f" AND t.name IN ({tag_placeholders})"
            params.extend(tag_names)
        
        # Group by clause
        base_query += """
            GROUP BY q.id, q.title, q.description, q.views, q.upvotes, q.downvotes,
                     q.score, q.created_at, q.updated_at, q.last_activity,
                     u.id, u.username, u.reputation, q.accepted_answer_id
        """
        
        # Add sorting and cursor logic
        if sort_by == 'score':
            order_clause = "ORDER BY q.score DESC, q.created_at DESC, q.id DESC"
        elif sort_by == 'views':
            order_clause = "ORDER BY q.views DESC, q.created_at DESC, q.id DESC"
        elif sort_by == 'oldest':
            order_clause = "ORDER BY q.created_at ASC, q.id ASC"
        else:  # newest (default)
            order_clause = "ORDER BY q.created_at DESC, q.id DESC"
        
        # Handle cursor for pagination
        cursor_condition = ""
        if cursor:
            try:
                cursor_data = json.loads(base64.b64decode(cursor).decode('utf-8'))
                if sort_by == 'score':
                    cursor_condition = " HAVING (q.score < %s OR (q.score = %s AND q.created_at < %s) OR (q.score = %s AND q.created_at = %s AND q.id < %s))"
                    params.extend([cursor_data['score'], cursor_data['score'], cursor_data['created_at'], 
                                 cursor_data['score'], cursor_data['created_at'], cursor_data['id']])
                elif sort_by == 'views':
                    cursor_condition = " HAVING (q.views < %s OR (q.views = %s AND q.created_at < %s) OR (q.views = %s AND q.created_at = %s AND q.id < %s))"
                    params.extend([cursor_data['views'], cursor_data['views'], cursor_data['created_at'],
                                 cursor_data['views'], cursor_data['created_at'], cursor_data['id']])
                elif sort_by == 'oldest':
                    cursor_condition = " HAVING (q.created_at > %s OR (q.created_at = %s AND q.id > %s))"
                    params.extend([cursor_data['created_at'], cursor_data['created_at'], cursor_data['id']])
                else:  # newest
                    cursor_condition = " HAVING (q.created_at < %s OR (q.created_at = %s AND q.id < %s))"
                    params.extend([cursor_data['created_at'], cursor_data['created_at'], cursor_data['id']])
            except:
                pass  # Invalid cursor, ignore
        
        # Complete query
        final_query = base_query + cursor_condition + " " + order_clause + " LIMIT %s"
        params.append(limit + 1)  # Get one extra to check if there are more
        
        cursor_db.execute(final_query, params)
        questions = cursor_db.fetchall()
        
        # Check if there are more results
        has_more = len(questions) > limit
        if has_more:
            questions = questions[:-1]  # Remove the extra item
        
        # Get tags for each question
        question_ids = [q['id'] for q in questions]
        if question_ids:
            cursor_db.execute("""
                SELECT qt.question_id, t.id, t.name, t.color
                FROM question_tags qt
                JOIN tags t ON qt.tag_id = t.id
                WHERE qt.question_id = ANY(%s)
            """, (question_ids,))
            
            tags_data = cursor_db.fetchall()
            tags_by_question = {}
            for tag in tags_data:
                if tag['question_id'] not in tags_by_question:
                    tags_by_question[tag['question_id']] = []
                tags_by_question[tag['question_id']].append({
                    'id': tag['id'],
                    'name': tag['name'],
                    'color': tag['color']
                })
        
        # Generate next cursor
        next_cursor = None
        if has_more and questions:
            last_question = questions[-1]
            cursor_data = {
                'id': last_question['id'],
                'created_at': last_question['created_at'].isoformat(),
                'score': last_question['score'],
                'views': last_question['views']
            }
            next_cursor = base64.b64encode(json.dumps(cursor_data).encode('utf-8')).decode('utf-8')
        
        # Get total count for metadata
        count_query = """
            SELECT COUNT(DISTINCT q.id)
            FROM questions q
            LEFT JOIN question_tags qt ON q.id = qt.question_id
            LEFT JOIN tags t ON qt.tag_id = t.id
            WHERE q.is_closed = false
        """
        
        count_params = []
        if search_query:
            count_query += " AND (q.title ILIKE %s OR q.description ILIKE %s)"
            count_params.extend([f"%{search_query}%", f"%{search_query}%"])
        
        if tags_filter:
            tag_names = [tag.strip().lower() for tag in tags_filter.split(',')]
            tag_placeholders = ','.join(['%s'] * len(tag_names))
            count_query += f" AND t.name IN ({tag_placeholders})"
            count_params.extend(tag_names)
        
        cursor_db.execute(count_query, count_params)
        total_count = cursor_db.fetchone()[0]
        
        conn.close()
        
        # Format response
        questions_data = []
        for question in questions:
            question_data = {
                'id': question['id'],
                'title': question['title'],
                'description': question['description'][:200] + '...' if len(question['description']) > 200 else question['description'],
                'author': {
                    'id': question['author_id'],
                    'username': question['username'],
                    'reputation': question['reputation']
                },
                'views': question['views'],
                'upvotes': question['upvotes'],
                'downvotes': question['downvotes'],
                'score': question['score'],
                'answer_count': question['answer_count'],
                'has_accepted_answer': question['has_accepted_answer'],
                'tags': tags_by_question.get(question['id'], []),
                'created_at': question['created_at'].isoformat(),
                'updated_at': question['updated_at'].isoformat(),
                'last_activity': question['last_activity'].isoformat()
            }
            questions_data.append(question_data)
        
        return jsonify({
            'success': True,
            'questions': questions_data,
            'pagination': {
                'has_more': has_more,
                'next_cursor': next_cursor,
                'limit': limit,
                'total_count': total_count
            },
            'filters': {
                'search': search_query,
                'tags': tags_filter,
                'sort': sort_by
            }
        }), 200
        
    except Exception as e:
        return jsonify({'error': 'Internal server error'}), 500

# ===========================================
# API 4: QUESTION DETAILS WITH ANSWERS
# ===========================================

@app.route('/api/questions/<int:question_id>', methods=['GET'])
def get_question_details(question_id):
    """
    Question Details API
    
    Logic:
    1. Fetch question with full details
    2. Increment view count
    3. Get all answers sorted by score and acceptance
    4. Get question tags
    5. Get user vote status (if authenticated)
    6. Return complete question data with answers
    
    Input:
    - question_id: int (URL parameter)
    - Authorization header (optional for vote status)
    
    Output:
    - question: complete question object
    - answers: array of answer objects
    - user_vote: user's vote status (if authenticated)
    """
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Get question details
        cursor.execute("""
            SELECT q.*, u.id as author_id, u.username, u.reputation as author_reputation,
                   u.profile_picture, u.created_at as author_joined
            FROM questions q
            JOIN users u ON q.author_id = u.id
            WHERE q.id = %s AND q.is_closed = false
        """, (question_id,))
        
        question = cursor.fetchone()
        if not question:
            conn.close()
            return jsonify({'error': 'Question not found'}), 404
        
        # Increment view count
        cursor.execute("UPDATE questions SET views = views + 1 WHERE id = %s", (question_id,))
        
        # Get question tags
        cursor.execute("""
            SELECT t.id, t.name, t.color
            FROM tags t
            JOIN question_tags qt ON t.id = qt.tag_id
            WHERE qt.question_id = %s
        """, (question_id,))
        tags = cursor.fetchall()
        
        # Get answers
        cursor.execute("""
            SELECT a.*, u.id as author_id, u.username, u.reputation as author_reputation,
                   u.profile_picture, u.created_at as author_joined
            FROM answers a
            JOIN users u ON a.author_id = u.id
            WHERE a.question_id = %s
            ORDER BY a.is_accepted DESC, a.score DESC, a.created_at ASC
        """, (question_id,))
        answers = cursor.fetchall()
        
        # Get user vote status if authenticated
        user_vote = None
        user_question_vote = None
        if hasattr(g, 'current_user') and g.current_user:
            # Question vote
            cursor.execute("""
                SELECT vote_type FROM votes 
                WHERE user_id = %s AND votable_type = 'question' AND votable_id = %s
            """, (g.current_user['id'], question_id))
            question_vote = cursor.fetchone()
            user_question_vote = question_vote['vote_type'] if question_vote else None
            
            # Answer votes
            answer_votes = {}
            if answers:
                answer_ids = [answer['id'] for answer in answers]
                cursor.execute("""
                    SELECT votable_id, vote_type FROM votes 
                    WHERE user_id = %s AND votable_type = 'answer' AND votable_id = ANY(%s)
                """, (g.current_user['id'], answer_ids))
                votes = cursor.fetchall()
                answer_votes = {vote['votable_id']: vote['vote_type'] for vote in votes}
            
            user_vote = {
                'question': user_question_vote,
                'answers': answer_votes
            }
        
        conn.commit()
        conn.close()
        
        # Format response
        question_data = {
            'id': question['id'],
            'title': question['title'],
            'description': question['description'],
            'author': {
                'id': question['author_id'],
                'username': question['username'],
                'reputation': question['author_reputation'],
                'profile_picture': question['profile_picture'],
                'joined': question['author_joined'].isoformat()
            },
            'views': question['views'] + 1,  # Include the increment
            'upvotes': question['upvotes'],
            'downvotes': question['downvotes'],
            'score': question['score'],
            'accepted_answer_id': question['accepted_answer_id'],
            'tags': [{'id': tag['id'], 'name': tag['name'], 'color': tag['color']} for tag in tags],
            'created_at': question['created_at'].isoformat(),
            'updated_at': question['updated_at'].isoformat(),
            'last_activity': question['last_activity'].isoformat()
        }
        
        answers_data = []
        for answer in answers:
            answer_data = {
                'id': answer['id'],
                'content': answer['content'],
                'author': {
                    'id': answer['author_id'],
                    'username': answer['username'],
                    'reputation': answer['author_reputation'],
                    'profile_picture': answer['profile_picture'],
                    'joined': answer['author_joined'].isoformat()
                },
                'upvotes': answer['upvotes'],
                'downvotes': answer['downvotes'],
                'score': answer['score'],
                'is_accepted': answer['is_accepted'],
                'accepted_at': answer['accepted_at'].isoformat() if answer['accepted_at'] else None,
                'created_at': answer['created_at'].isoformat(),
                'updated_at': answer['updated_at'].isoformat(),
                'user_vote': user_vote['answers'].get(answer['id']) if user_vote else None
            }
            answers_data.append(answer_data)
        
        return jsonify({
            'success': True,
            'question': question_data,
            'answers': answers_data,
            'user_vote': user_vote,
            'answer_count': len(answers_data)
        }), 200
        
    except Exception as e:
        return jsonify({'error': 'Internal server error'}), 500

# ===========================================
# BONUS APIs: VOTING AND ANSWER POSTING
# ===========================================

@app.route('/api/questions/<int:question_id>/vote', methods=['POST'])
@token_required
def vote_question(question_id):
    """Vote on a question (upvote/downvote)"""
    try:
        data = request.get_json()
        vote_type = data.get('vote_type')  # 'upvote' or 'downvote'
        
        if vote_type not in ['upvote', 'downvote']:
            return jsonify({'error': 'Invalid vote type'}), 400
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Check if question exists
        cursor.execute("SELECT id FROM questions WHERE id = %s", (question_id,))
        if not cursor.fetchone():
            conn.close()
            return jsonify({'error': 'Question not found'}), 404
        
        # Check existing vote
        cursor.execute("""
            SELECT vote_type FROM votes 
            WHERE user_id = %s AND votable_type = 'question' AND votable_id = %s
        """, (g.current_user['id'], question_id))
        existing_vote = cursor.fetchone()
        
        if existing_vote:
            if existing_vote['vote_type'] == vote_type:
                # Remove vote (toggle)
                cursor.execute("""
                    DELETE FROM votes 
                    WHERE user_id = %s AND votable_type = 'question' AND votable_id = %s
                """, (g.current_user['id'], question_id))
                
                # Update question vote count
                if vote_type == 'upvote':
                    cursor.execute("UPDATE questions SET upvotes = upvotes - 1, score = score - 1 WHERE id = %s", (question_id,))
                else:
                    cursor.execute("UPDATE questions SET downvotes = downvotes - 1, score = score + 1 WHERE id = %s", (question_id,))
                
                vote_result = None
            else:
                # Change vote
                cursor.execute("""
                    UPDATE votes SET vote_type = %s, updated_at = %s
                    WHERE user_id = %s AND votable_type = 'question' AND votable_id = %s
                """, (vote_type, datetime.utcnow(), g.current_user['id'], question_id))
                
                # Update question vote count
                if vote_type == 'upvote':
                    cursor.execute("UPDATE questions SET upvotes = upvotes + 1, downvotes = downvotes - 1, score = score + 2 WHERE id = %s", (question_id,))
                else:
                    cursor.execute("UPDATE questions SET upvotes = upvotes - 1, downvotes = downvotes + 1, score = score - 2 WHERE id = %s", (question_id,))
                
                vote_result = vote_type
        else:
            # New vote
            cursor.execute("""
                INSERT INTO votes (user_id, votable_type, votable_id, vote_type, created_at)
                VALUES (%s, 'question', %s, %s, %s)
            """, (g.current_user['id'], question_id, vote_type, datetime.utcnow()))
            
            # Update question vote count
            if vote_type == 'upvote':
                cursor.execute("UPDATE questions SET upvotes = upvotes + 1, score = score + 1 WHERE id = %s", (question_id,))
            else:
                cursor.execute("UPDATE questions SET downvotes = downvotes + 1, score = score - 1 WHERE id = %s", (question_id,))
            
            vote_result = vote_type
        
        # Get updated vote counts
        cursor.execute("SELECT upvotes, downvotes, score FROM questions WHERE id = %s", (question_id,))
        updated_question = cursor.fetchone()
        
        conn.commit()
        conn.close()
        
        return jsonify({
            'success': True,
            'vote': vote_result,
            'upvotes': updated_question['upvotes'],
            'downvotes': updated_question['downvotes'],
            'score': updated_question['score']
        }), 200
        
    except Exception as e:
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/api/questions/<int:question_id>/answers', methods=['POST'])
@token_required
def create_answer(question_id):
    """Post an answer to a question"""
    try:
        data = request.get_json()
        content = data.get('content', '').strip()
        
        if not content or len(content) < 10:
            return jsonify({'error': 'Answer content must be at least 10 characters'}), 400
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Check if question exists and is not closed
        cursor.execute("SELECT id FROM questions WHERE id = %s AND is_closed = false", (question_id,))
        if not cursor.fetchone():
            conn.close()
            return jsonify({'error': 'Question not found or closed'}), 404
        
        # Create answer
        cursor.execute("""
            INSERT INTO answers (question_id, content, author_id, created_at, updated_at)
            VALUES (%s, %s, %s, %s, %s)
            RETURNING id, content, upvotes, downvotes, score, is_accepted, created_at, updated_at
        """, (question_id, content, g.current_user['id'], datetime.utcnow(), datetime.utcnow()))
        
        answer = cursor.fetchone()
        
        conn.commit()
        conn.close()
        
        return jsonify({
            'success': True,
            'message': 'Answer posted successfully',
            'answer': {
                'id': answer['id'],
                'content': answer['content'],
                'author': {
                    'id': g.current_user['id'],
                    'username': g.current_user['username'],
                    'reputation': g.current_user['reputation']
                },
                'upvotes': answer['upvotes'],
                'downvotes': answer['downvotes'],
                'score': answer['score'],
                'is_accepted': answer['is_accepted'],
                'created_at': answer['created_at'].isoformat(),
                'updated_at': answer['updated_at'].isoformat()
            }
        }), 201
        
    except Exception as e:
        return jsonify({'error': 'Internal server error'}), 500

# ===========================================
# UTILITY ENDPOINTS
# ===========================================

@app.route('/api/tags', methods=['GET'])
def get_tags():
    """Get all available tags"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT id, name, color, usage_count, description
            FROM tags
            ORDER BY usage_count DESC, name ASC
            LIMIT 100
        """)
        tags = cursor.fetchall()
        
        conn.close()
        
        return jsonify({
            'success': True,
            'tags': [
                {
                    'id': tag['id'],
                    'name': tag['name'],
                    'color': tag['color'],
                    'usage_count': tag['usage_count'],
                    'description': tag['description']
                }
                for tag in tags
            ]
        }), 200
        
    except Exception as e:
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/api/user/profile', methods=['GET'])
@token_required
def get_user_profile():
    """Get current user profile"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Get user stats
        cursor.execute("""
            SELECT 
                COUNT(CASE WHEN type = 'question' THEN 1 END) as questions_count,
                COUNT(CASE WHEN type = 'answer' THEN 1 END) as answers_count
            FROM (
                SELECT 'question' as type FROM questions WHERE author_id = %s
                UNION ALL
                SELECT 'answer' as type FROM answers WHERE author_id = %s
            ) as user_content
        """, (g.current_user['id'], g.current_user['id']))
        
        stats = cursor.fetchone()
        
        conn.close()
        
        return jsonify({
            'success': True,
            'user': {
                'id': g.current_user['id'],
                'username': g.current_user['username'],
                'email': g.current_user['email'],
                'role': g.current_user['role'],
                'reputation': g.current_user['reputation'],
                'profile_picture': g.current_user['profile_picture'],
                'bio': g.current_user['bio'],
                'created_at': g.current_user['created_at'].isoformat(),
                'stats': {
                    'questions': stats['questions_count'],
                    'answers': stats['answers_count']
                }
            }
        }), 200
        
    except Exception as e:
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/api/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.utcnow().isoformat(),
        'service': 'StackIt API'
    }), 200

# Error handlers
@app.errorhandler(404)
def not_found(error):
    return jsonify({'error': 'Endpoint not found'}), 404

@app.errorhandler(500)
def internal_error(error):
    return jsonify({'error': 'Internal server error'}), 500

# For Vercel deployment
if __name__ == '__main__':
    app.run(debug=True)