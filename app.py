import random
from datetime import datetime, timezone
import re
from email.policy import default
from flask import Flask, jsonify, request, session, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from flask_socketio import SocketIO, join_room, send, emit
import os
from werkzeug.utils import secure_filename
from datetime import datetime, timedelta
from sqlalchemy import or_, and_, desc
from flask import request, jsonify
import traceback
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.exc import IntegrityError
import jwt

app = Flask(__name__)
app.config[
    'SQLALCHEMY_DATABASE_URI'] = "postgresql://inshaapp2_render_example_user:YyxBMcdk0vIsMKU8i2IWEiINI41BVyLM@dpg-d55cjvemcj7s73f9e5jg-a.frankfurt-postgres.render.com/inshaapp2_render_example"
socketio = SocketIO(app)
db = SQLAlchemy(app)

# Set the upload folder configuration
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['SECRET_KEY'] = 'a8f4c2e1b5d6f7a8c9e0d1f2b3a4c5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2'
SECRET_KEY = app.config['SECRET_KEY']

# Ensure the uploads folder exists
if not os.path.exists(app.config['UPLOAD_FOLDER']):
    os.makedirs(app.config['UPLOAD_FOLDER'])

UPLOAD_FOLDER = 'uploads/'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER


# Check if the file extension is allowed
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


class User(db.Model):
    __tablename__ = 'userdetails'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    email = db.Column(db.String(200), unique=True, nullable=False)
    password = db.Column(db.String, nullable=False)


class UserProfile(db.Model):
    __tablename__ = 'user_profile'

    id = db.Column(db.Integer, primary_key=True)
    user_auth_id = db.Column(db.Integer,db.ForeignKey('userdetails.id'),nullable=False,unique=True)
    firstname = db.Column(db.String(255))
    lastname = db.Column(db.String(255))
    gender = db.Column(db.String(50))
    email = db.Column(db.String(200))
    age = db.Column(db.String(10))
    phone_number = db.Column(db.String(50))
    sect = db.Column(db.String(50))
    lookingfor = db.Column(db.String(255))
    
    user = db.relationship('User', backref=db.backref('profile', uselist=False))


class UserInfo(db.Model):
    __tablename__ = 'user_info'

    id = db.Column(db.Integer, primary_key=True)
    user_profile_id = db.Column(db.Integer,db.ForeignKey('user_profile.id'),nullable=False,unique=True)
    hobbies = db.Column(db.ARRAY(db.String))
    preferences = db.Column(db.ARRAY(db.String))
    bio = db.Column(db.Text)
    alcoholstatus = db.Column(db.String(25))
    childrenstatus = db.Column(db.String(25))
    maritalstatus = db.Column(db.String(25))
    smokestatus = db.Column(db.String(25))
    halalfood = db.Column(db.String(25))

    profile = db.relationship('UserProfile',backref=db.backref('info', uselist=False))


class UserCharacter(db.Model):
    __tablename__ = 'user_character'

    id = db.Column(db.Integer, primary_key=True)
    user_profile_id = db.Column(db.Integer,db.ForeignKey('user_profile.id'),nullable=False,unique=True)
    muslimstatus = db.Column(db.String(25))
    practicing = db.Column(db.String(25))
    nationality = db.Column(db.String(50))

    personality_type = db.Column(db.String(100))

    profile = db.relationship('UserProfile',backref=db.backref('character', uselist=False))


class UserImages(db.Model):
    __tablename__ = 'userImage'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    user_auth_id = db.Column(db.Integer, db.ForeignKey('userdetails.id'), nullable=False)
    email = db.Column(db.String(200))  # Ensure this column exists
    imageString = db.Column(db.String())
    user = db.relationship('User', backref=db.backref('user_image', lazy=True))


class Message(db.Model):
    __tablename__ = 'messages'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('userdetails.id'), nullable=False)
    receiver_id = db.Column(db.Integer, db.ForeignKey('userdetails.id'), nullable=False)
    message = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.now(timezone.utc))

    sender = db.relationship('User', foreign_keys=[sender_id], backref=db.backref('sent_messages', lazy=True))
    receiver = db.relationship('User', foreign_keys=[receiver_id], backref=db.backref('received_messages', lazy=True))


class EventHost(db.Model):
    __tablename__ = 'event_hosts'

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    name = db.Column(db.String(100), unique=True, nullable=False)


class EventCategory(db.Model):
    __tablename__ = 'event_categories'

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    name = db.Column(db.String(100), unique=True, nullable=False)


class LocationInfo(db.Model):
    __tablename__ = 'locationInfo'

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    maxAttendees = db.Column(db.Integer)
    maleAttendees = db.Column(db.Integer)
    femaleAttendees = db.Column(db.Integer)
    date = db.Column(db.String(200))
    time = db.Column(db.String(20))
    location = db.Column(db.String(200))
    description = db.Column(db.String(500))  # NEW FIELD    
    lat = db.Column(db.Float)
    lng = db.Column(db.Float)
    totalPrice = db.Column(db.Integer)
    checkin_closed = db.Column(db.Boolean, default=False)

    # NEW FIELD
    matchmake = db.Column(db.Boolean, default=False)

    event_category_id = db.Column(db.Integer, db.ForeignKey('event_categories.id'))
    event_category = db.relationship("EventCategory")
    
    # Host (NEW)
    event_host_id = db.Column(db.Integer, db.ForeignKey('event_hosts.id'))
    event_host = db.relationship("EventHost")

    current_round = db.Column(db.Integer, default=1)


class CheckIn(db.Model):
    __tablename__ = 'checkins'

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    user_id = db.Column(db.Integer, db.ForeignKey('userdetails.id'), nullable=False)
    location_id = db.Column(db.Integer, db.ForeignKey('locationInfo.id'), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.now(timezone.utc))

    user = db.relationship('User', backref=db.backref('checkins', lazy=True))
    location = db.relationship('LocationInfo', backref=db.backref('checkins', lazy=True))

    __table_args__ = (
        db.UniqueConstraint('user_id', 'location_id', name='unique_user_location_checkin'),
    )


class Attendance(db.Model):
    __tablename__ = 'attendance'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    user_id = db.Column(db.Integer, db.ForeignKey('userdetails.id'), nullable=False)
    location_id = db.Column(db.Integer, db.ForeignKey('locationInfo.id'), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.now(timezone.utc))
    hasAttended = db.Column(db.Boolean, default=False)

    user = db.relationship('User', backref=db.backref('attendances', lazy=True))
    location = db.relationship('LocationInfo', backref=db.backref('attendances', lazy=True))

    __table_args__ = (
        db.UniqueConstraint('user_id', 'location_id', name='unique_user_location_attendance'),
    )


class UserPreference(db.Model):
    __tablename__ = 'user_preference'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    user_id = db.Column(db.Integer, db.ForeignKey('userdetails.id'), nullable=False)
    preferred_user_id = db.Column(db.Integer, db.ForeignKey('userdetails.id'), nullable=False)
    preference = db.Column(db.String(20), nullable=False)  # 'like', 'reject', 'save_later'
    timestamp = db.Column(db.DateTime, default=datetime.now(timezone.utc))

    # Relationships
    user = db.relationship('User', foreign_keys=[user_id], backref=db.backref('preferences', lazy=True))
    preferred_user = db.relationship('User', foreign_keys=[preferred_user_id],
                                     backref=db.backref('preferred_by', lazy=True))


class Match(db.Model):
    __tablename__ = 'matches'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    user1_id = db.Column(db.Integer, db.ForeignKey('userdetails.id'), nullable=False)
    user2_id = db.Column(db.Integer, db.ForeignKey('userdetails.id'), nullable=False)
    match_date = db.Column(db.DateTime, default=datetime.now(timezone.utc))
    visible_after = db.Column(db.Integer)
    status = db.Column(db.String(20), default='pending')  # 'pending', 'active', 'deleted'
    location_id = db.Column(db.Integer, db.ForeignKey('locationInfo.id'), nullable=True)

    # Relationships
    user1 = db.relationship('User', foreign_keys=[user1_id], backref=db.backref('matches_as_user1', lazy=True))
    user2 = db.relationship('User', foreign_keys=[user2_id], backref=db.backref('matches_as_user2', lazy=True))
    location = db.relationship('LocationInfo', backref=db.backref('matches_at_location', lazy=True))


with app.app_context():
    # Match.__table__.drop(db.engine)
    # UserPreference.__table__.drop(db.engine)
    # Attendance.__table__.drop(db.engine)
    # CheckIn.__table__.drop(db.engine)
    db.create_all()


# API Endpoints

def has_user_checked_in(user_id, location_id):
    return db.session.query(CheckIn).filter_by(user_id=user_id, location_id=location_id).first() is not None

def create_token(user):
    payload = {
        "user_id": user.id,
        "exp": datetime.utcnow() + timedelta(days=7)
    }
    return jwt.encode(payload, app.config['SECRET_KEY'], algorithm="HS256")


def get_current_user_from_token():
    auth_header = request.headers.get('Authorization', None)
    if not auth_header or not auth_header.startswith("Bearer "):
        print("No Authorization header or wrong format")
        return None

    token = auth_header.split(" ")[1]
    try:
        payload = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        print("Decoded JWT payload:", payload)
        user_id = payload.get('user_id')
        user = User.query.get(user_id)
        print("Fetched user from DB:", user)
        return user
    except jwt.ExpiredSignatureError:
        print("JWT expired")
        return None
    except jwt.InvalidTokenError as e:
        print("JWT invalid:", e)
        return None



@app.route('/sign-in', methods=['POST'])
def sign_in():
    try:
        data = request.get_json()
        email = data.get('email')
        password = data.get('password')

        if not email or not password:
            return jsonify({'error': 'Email and password are required'}), 400

        user = User.query.filter_by(email=email).first()
        if not user or password != user.password:
            return jsonify({'message': 'Invalid credentials'}), 401

        payload = {
            'user_id': user.id,
            'exp': datetime.utcnow() + timedelta(days=7)
        }
        token = jwt.encode(payload, app.config['SECRET_KEY'], algorithm='HS256')
        if isinstance(token, bytes):
            token = token.decode('utf-8')

        return jsonify({'message': 'Sign in successful', 'token': token}), 200
    except Exception as e:
        print("Sign-in error:", e)
        return jsonify({'error': str(e)}), 500


@app.route('/sign-in', methods=['GET'])
def get_signin_data():
    signin = User.query.all()
    data = [
        {
            'id': rel.id,
            'email': rel.email,
            'password': rel.password,
        }
        for rel in signin
    ]
    return jsonify(data)


# USER SIGNIN METHOD -> End

# METHOD TO GET AUTHENTICATED USERS LIST -> Start

@app.get("/users")
def home():
    tasks = User.query.all()
    task_list = [
        {'id': task.id, 'email': task.email, 'password': task.password} for task in tasks
    ]
    return jsonify({"user_details": task_list})


# POST USER CREDENTIALS TO DATABASE

@app.route('/users', methods=['POST'])
def postData():
    try:
        data = request.get_json()
        new_email = data.get('email')
        new_password = data.get('password')

        if not new_email or not new_password:
            return jsonify({'error': 'Email and password are required'}), 400

        # Validate email
        email_regex = r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$'
        if not re.match(email_regex, new_email):
            return jsonify({'message': 'Invalid email format'}), 400

        # Check if email exists
        if User.query.filter_by(email=new_email).first():
            return jsonify({'message': 'Email already exists'}), 400

        # Create user
        new_user = User(email=new_email, password=new_password)
        db.session.add(new_user)
        db.session.commit()

        # Create token
        payload = {
            'user_id': new_user.id,
            'exp': datetime.utcnow() + timedelta(days=7)
        }
        token = jwt.encode(payload, SECRET_KEY, algorithm='HS256')
        if isinstance(token, bytes):
            token = token.decode('utf-8')

        return jsonify({'message': "New User added", 'token': token}), 201

    except Exception as e:
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500


# I changed this, be aware!
def process_potential_match(user1_id, user2_id):
    """
    Process potential match between two users based on their preferences and location.
    """

    # Get preferences in both directions
    pref1 = UserPreference.query.filter_by(user_id=user1_id, preferred_user_id=user2_id).first()
    pref2 = UserPreference.query.filter_by(user_id=user2_id, preferred_user_id=user1_id).first()

    # If either preference doesn't exist yet, no match to process
    if not pref1 or not pref2:
        return

    # Check if there's an existing match
    existing_match = Match.query.filter(
        or_(
            and_(Match.user1_id == user1_id, Match.user2_id == user2_id),
            and_(Match.user1_id == user2_id, Match.user2_id == user1_id)
        )
    ).first()

    # Case I: Both users like each other
    if pref1.preference == 'like' and pref2.preference == 'like':
        if existing_match:
            # Update match status
            existing_match.status = 'active'
            existing_match.visible_after = get_unix_timestamp(datetime.now(timezone.utc) + timedelta(minutes=20))
        else:
            # Create new match with 20 minute delay
            new_match = Match(
                user1_id=user1_id,
                user2_id=user2_id,
                visible_after=get_unix_timestamp(datetime.now(timezone.utc) + timedelta(minutes=20)),
                status='active'
            )
            db.session.add(new_match)
    # Case II: One or both users rejected
    elif pref1.preference == 'reject' or pref2.preference == 'reject':
        if existing_match:
            # Mark match as deleted
            existing_match.status = 'deleted'
    # Case III & IV: Save for later scenarios
    elif pref1.preference == 'save_later' or pref2.preference == 'save_later':
        # Only proceed if neither preference is 'reject'
        if pref1.preference != 'reject' and pref2.preference != 'reject':
            if not existing_match:
                # Create pending match
                new_match = Match(
                    user1_id=user1_id,
                    user2_id=user2_id,
                    status='pending',
                    visible_after=get_unix_timestamp(datetime.now(timezone.utc))  # Visible immediately, but pending
                )
                db.session.add(new_match)


def get_match_score(user1_data, user2_data):
    """Calculate a simple match score between two users based on age and hobbies"""
    score = 0

    # Age compatibility
    try:
        age_diff = abs(float(user1_data.age) - float(user2_data.age))
        if age_diff <= 5:
            score += 30
        elif age_diff <= 10:
            score += 20
        elif age_diff <= 15:
            score += 10
    except (ValueError, TypeError):
        pass

    # Common hobbies
    if user1_data.hobbies and user2_data.hobbies:
        common_hobbies = set(user1_data.hobbies).intersection(set(user2_data.hobbies))
        score += min(len(common_hobbies) * 10, 30)

    return score


def get_match_status(user_id, other_user_id):
    try:

        # Get user preferences
        user_pref = UserPreference.query.filter_by(
            user_id=user_id, preferred_user_id=other_user_id
        ).first()

        other_pref = UserPreference.query.filter_by(
            user_id=other_user_id, preferred_user_id=user_id
        ).first()

        current_time = datetime.now(timezone.utc)

        matches = Match.query.filter(
            or_(
                Match.user1_id == user_id,
                Match.user2_id == user_id
            ),
            Match.status != 'deleted',
            Match.visible_after <= current_time
        ).all()
        for match in matches:
            # Determine the other user ID
            matched_user_id = match.user2_id if match.user1_id == user_id else match.user1_id

            # Checks if the required match is found else continue
            if matched_user_id != other_user_id:
                continue

            # Determine match status from user's perspective
            if match.status == 'active':
                # Both liked each other
                display_status = 'matched'
                show_message_button = True
            else:  # status is 'pending'
                if user_pref and user_pref.preference == 'save_later':
                    display_status = 'decide'  # User needs to decide
                    show_message_button = False
                elif other_pref and other_pref.preference == 'save_later':
                    display_status = 'pending'  # Waiting for other user
                    show_message_button = False
                else:
                    display_status = 'pending'  # Generic pending
                    show_message_button = False
            return [display_status, show_message_button]
        return ""
    except Exception as e:
        print(f"Error in get_status: {str(e)}")
        return ""


def get_user_matches(user_id, limit=5):
    """Get top matches for a user"""
    try:
        # First get the user's gender
        user = UserProfile.query.filter_by(user_auth_id=user_id).first()
        if not user:
            print(f"No user found for ID: {user_id}")
            return []

        # Normalize gender values for consistent comparison
        user_gender = user.gender.lower() if user.gender else None

        # Get users of opposite gender, handling different gender formats
        if user_gender == 'men' or user_gender == 'man':
            target_gender = ['Woman', 'woman', 'Women', 'women', 'Female', 'female']
        elif user_gender == 'woman' or user_gender == 'women':
            target_gender = ['Men', 'men', 'Man', 'man', 'Male', 'male']
        else:
            # If gender is something else or not specified, get any user
            target_gender = ['Men', 'men', 'Man', 'man', 'Male', 'male', 'Woman', 'woman', 'Women', 'women', 'Female',
                             'female']

        # Get existing matches and preferences to avoid duplicates
        existing_matches = Match.query.filter(
            or_(Match.user1_id == user_id, Match.user2_id == user_id),
            # and_(Match.status != 'deleted', Match.status != 'active')
            Match.status != 'deleted'
        ).all()

        existing_preferences = UserPreference.query.filter_by(user_id=user_id).all()

        # Create sets of already matched/preferred user IDs
        matched_users = set()
        for match in existing_matches:
            if match.user1_id == user_id:
                matched_users.add(match.user2_id)
            else:
                matched_users.add(match.user1_id)

        preferred_users = set([pref.preferred_user_id for pref in existing_preferences])

        # Find potential matches (users of opposite gender not already matched/preferred)
        potential_matches = UserProfile.query.filter(
            UserProfile.gender.in_(target_gender),
            UserProfile.user_auth_id != user_id,
            ~UserProfile.user_auth_id.in_(matched_users.union(preferred_users))
        ).all()

        # Calculate match scores and sort
        scored_matches = []
        for potential_match in potential_matches:
            score = get_match_score(user, potential_match)
            scored_matches.append((potential_match, score))

        # Sort by score (highest first)
        scored_matches.sort(key=lambda x: x[1], reverse=True)

        # Format results with top matches
        result = []
        for match, score in scored_matches[:limit]:
            # Get user image if available
            user_image = UserImages.query.filter_by(user_auth_id=match.user_auth_id).first()
            image_url = None
            if user_image and user_image.imageString:
                image_url = f"/uploads/{user_image.imageString}"

            result.append({
                'user_id': match.user_auth_id,
                'email': match.email,
                'firstname': match.firstname,
                'lastname': match.lastname,
                'preferences': match.preferences,
                'age': match.age,
                'bio': match.bio,
                'hobbies': match.hobbies,
                'match_score': score,
                'image_url': image_url
            })

        return result
    except Exception as e:
        print(f"Error in get_user_matches: {str(e)}")
        return []


def match_all_users():
    """Match all users with someone from opposite gender"""
    try:
        # Get all users with complete profiles
        all_users = UserProfile.query.all()

        # Initialize results dictionary
        matches = {}

        used_users = set()  # Track who is already matched # Work: 41410282

        # Get all existing matches and preferences
        existing_matches = Match.query.all()
        existing_preferences = UserPreference.query.all()

        # Create sets of user pairs who already have matches or preferences
        matched_pairs = set()
        for match in existing_matches:
            matched_pairs.add((match.user1_id, match.user2_id))
            matched_pairs.add((match.user2_id, match.user1_id))  # Add reverse pair too

        preference_pairs = set()
        for pref in existing_preferences:
            preference_pairs.add((pref.user_id, pref.preferred_user_id))

        # Group users by gender
        gender_groups = {}
        for user in all_users:
            gender = user.gender.lower() if user.gender else "unknown"
            if gender not in gender_groups:
                gender_groups[gender] = []
            gender_groups[gender].append(user)

        # Map genders to opposite genders
        opposite_genders = {
            "men": "women",
            "man": "woman",
            "male": "female",
            "women": "men",
            "woman": "man",
            "female": "male"
        }

        # Process each user
        for user in all_users:

            # Old logic to skip
            # Skip if user already has matches in the result
            # if user.user_auth_id in matches:
            #    continue

            # # Skip if user already has matches in the result
            if user.user_auth_id in used_users:  # Work: 41410282
                continue  # Work: 41410282

            user_gender = user.gender.lower() if user.gender else "unknown"

            # Determine opposite gender
            opposite_gender = opposite_genders.get(user_gender)

            # If we can't determine opposite gender, skip
            if not opposite_gender or opposite_gender not in gender_groups:
                continue

            # Find best match among opposite gender
            best_score = -1
            best_match = None

            for potential_match in gender_groups.get(opposite_gender, []):
                # Skip if they already have a match or preference
                if ((user.user_auth_id, potential_match.user_auth_id) in matched_pairs or
                        (user.user_auth_id, potential_match.user_auth_id) in preference_pairs or
                        (potential_match.user_auth_id, user.user_auth_id) in preference_pairs or
                        potential_match.user_auth_id in matches):  # Skip if already matched in this run
                    continue

                score = get_match_score(user, potential_match)
                if score > best_score:
                    best_score = score
                    best_match = potential_match

            # Create the match
            if best_match:
                # Get profile images if available
                user_image = UserImages.query.filter_by(user_auth_id=user.user_auth_id).first()
                match_image = UserImages.query.filter_by(user_auth_id=best_match.user_auth_id).first()

                user_image_url = f"/uploads/{user_image.imageString}" if user_image and user_image.imageString else None
                match_image_url = f"/uploads/{match_image.imageString}" if match_image and match_image.imageString else None

                # Add match for current user
                matches[user.user_auth_id] = {
                    'match_id': best_match.user_auth_id,
                    'firstname': best_match.firstname,
                    'age': best_match.age,
                    'score': best_score,
                    'image_url': match_image_url
                }

                # Add match for the matched user
                matches[best_match.user_auth_id] = {
                    'match_id': user.user_auth_id,
                    'firstname': user.firstname,
                    'age': user.age,
                    'score': best_score,
                    'image_url': user_image_url
                }

                # Mark both as used # Work: 41410282
                used_users.add(user.user_auth_id)  # Work: 41410282
                used_users.add(best_match.user_auth_id)  # Work: 41410282

                # Mark this pair as matched to avoid duplicates
                matched_pairs.add((user.user_auth_id, best_match.user_auth_id))
                matched_pairs.add((best_match.user_auth_id, user.user_auth_id))

        return matches

    except Exception as e:
        print(f"Error in match_all_users: {str(e)}")
        return {}


def get_unix_timestamp(datatime):
    # Convert to Unix timestamp (seconds since epoch)
    unix_ts = int(datatime.timestamp())

    return unix_ts


def trigger_matchmaking_for_location(location_id):
    """
    Trigger automatic matchmaking for all checked-in users at a specific location.
    This is called when all slots are filled or check-in period ends.
    """
    try:
        # Get all users who checked in to this location
        checkins = CheckIn.query.filter_by(location_id=location_id).all()
        checked_in_user_ids = [checkin.user_id for checkin in checkins]

        print(f"Triggered matchmaking for location {location_id}")

        if len(checked_in_user_ids) < 2:
            print(f"Not enough users checked in for matchmaking at location {location_id}")
            return None

        # Get location details for matchmaking
        location = LocationInfo.query.get(location_id)
        if not location:
            print(f"Location {location_id} not found")
            return None

        # Get the actual checked-in users
        checked_in_users = []
        for user_id in checked_in_user_ids:
            user = User.query.get(user_id)
            if user:
                checked_in_users.append(user)

        if len(checked_in_users) < 2:
            print(f"Not enough valid users for matchmaking at location {location_id}")
            return None

        # Query to get all existing active matches at this location for all the checked in users
        existing_matches = (
            db.session.query(Match)
            .filter(
                Match.status == 'active',
                or_(
                    Match.user1_id.in_(checked_in_user_ids),
                    Match.user2_id.in_(checked_in_user_ids)
                ),
                Match.location_id == location_id,
            )
            .all()
        )
        existing_matches_tuple = []
        if existing_matches:
            for match in existing_matches:
                user_1 = match.user1_id
                user_2 = match.user2_id
                existing_matches_tuple.append((user_1, user_2))
                existing_matches_tuple.append((user_2, user_1))

        # Separate users by gender for proper matching
        male_users = []
        female_users = []

        for user in checked_in_users:
            user_data = UserProfile.query.filter_by(user_auth_id=user.id).first()
            if user_data and user_data.gender:
                gender = user_data.gender.lower()
                if gender in ['men', 'man', 'male']:
                    male_users.append(user)
                elif gender in ['women', 'woman', 'female']:
                    female_users.append(user)

        print(f"Checked-in users: {len(checked_in_users)}, Male: {len(male_users)}, Female: {len(female_users)}")

        # Create ALL possible matches between opposite genders
        matches_created = 0
        users_left_out = []

        # Handle odd numbers with fair rotation
        if len(male_users) != len(female_users):
            # Determine which gender has more users
            if len(male_users) > len(female_users):
                excess_users = male_users
                base_users = female_users
                excess_gender = "male"
            else:
                excess_users = female_users
                base_users = male_users
                excess_gender = "female"

            # Get the last matchmaking session to determine who was left out
            last_matchmaking = Match.query.order_by(Match.match_date.desc()).first()

            # Implement fair rotation
            if last_matchmaking:
                # Check who was left out in the last session
                last_match_date = last_matchmaking.match_date
                recent_matches = Match.query.filter(
                    Match.match_date >= last_match_date - timedelta(hours=1)
                ).all()

                # Get users who were matched recently
                recently_matched = set()
                for match in recent_matches:
                    recently_matched.add(match.user1_id)
                    recently_matched.add(match.user2_id)

                # Find users who were NOT matched recently (potential candidates to leave out)
                unmatched_candidates = [user for user in excess_users if user.id not in recently_matched]

                if unmatched_candidates:
                    # Leave out a different user this time
                    user_to_leave_out = random.choice(unmatched_candidates)
                    excess_users.remove(user_to_leave_out)
                    users_left_out.append(user_to_leave_out)
                    print(
                        f"Fair rotation: Leaving out {excess_gender} user {user_to_leave_out.id} ({user_to_leave_out.email}) this time")
                else:
                    # If no recent matches, just leave out a random user
                    user_to_leave_out = random.choice(excess_users)
                    excess_users.remove(user_to_leave_out)
                    users_left_out.append(user_to_leave_out)
                    print(
                        f"Random rotation: Leaving out {excess_gender} user {user_to_leave_out.id} ({user_to_leave_out.email})")
            else:
                # First time matchmaking, leave out a random user
                user_to_leave_out = random.choice(excess_users)
                excess_users.remove(user_to_leave_out)
                users_left_out.append(user_to_leave_out)
                print(
                    f"First time: Leaving out {excess_gender} user {user_to_leave_out.id} ({user_to_leave_out.email})")

            # Now we have equal numbers - use the updated lists
            if excess_gender == "male":
                male_users = excess_users
                female_users = base_users
            else:
                male_users = base_users
                female_users = excess_users

        # Shuffle both lists to ensure random matching
        random.shuffle(male_users)
        random.shuffle(female_users)

        # Create matches one-to-one
        for i in range(min(len(male_users), len(female_users))):
            male_user = male_users[i]
            female_user = female_users[i]

            # CRITICAL FIX: Prevent self-matching
            if male_user.id == female_user.id:
                print(f"SKIPPING: Self-match detected for user {male_user.id}")
                continue

            if (male_user.id, female_user.id) in existing_matches_tuple:
                print(f"SKIPPING: Existing match found ({male_user.id}, {female_user.id}) with active status")
                continue

            # Get user preferences
            user_pref = UserPreference.query.filter_by(
                user_id=male_user.id, preferred_user_id=female_user.id
            ).first()

            other_pref = UserPreference.query.filter_by(
                user_id=female_user.id, preferred_user_id=male_user.id
            ).first()

            if user_pref and user_pref.preference == 'reject':
                print(f"SKIPPING: Preference already rejected for user {female_user.id} by user {male_user.id}")
                continue
            elif other_pref and other_pref.preference == 'reject':
                print(f"SKIPPING: Preference already rejected for user {male_user.id} by user {female_user.id}")
                continue

            visible_after_timestamp = get_unix_timestamp(datetime.now(timezone.utc) + timedelta(minutes=20))
            # Create mutual match
            new_match = Match(
                user1_id=male_user.id,
                user2_id=female_user.id,
                status='active',
                location_id=location_id,
                visible_after=visible_after_timestamp
            )
            db.session.add(new_match)
            matches_created += 1
            print(
                f"At: {datetime.now(timezone.utc)}, Created mutual match: User {male_user.id} ({male_user.email}) ↔ User {female_user.id} ({female_user.email}), visible after: {visible_after_timestamp}")

        db.session.commit()
        print(f"Automatic matchmaking completed for location {location_id}: {matches_created} matches created")

        # Return summary for debugging
        return {
            'location_id': location_id,
            'total_users': len(checked_in_users),
            'male_users': len(male_users),
            'female_users': len(female_users),
            'matches_created': matches_created,
            'users_left_out': [user.email for user in users_left_out],
            'matches_per_user': matches_created // len(male_users) if male_users else 0
        }

    except Exception as e:
        print(f"Error in automatic matchmaking: {str(e)}")
        db.session.rollback()
        return None

# METHOD TO GET AUTHENTICATED USERS LIST -> End

# Fetch loggedinusers info -> Start

@app.route("/loggedinUserProfileData", methods=["GET"])
def logged_in_user_profile():
    """Return full profile data for the logged-in user."""
    user = get_current_user_from_token()
    if not user:
        return jsonify({"error": "Unauthorized"}), 401

    # Fetch profile
    profile = UserProfile.query.filter_by(user_auth_id=user.id).first()
    if not profile:
        return jsonify({"error": "Profile not found"}), 404

    info = profile.info
    character = profile.character
    images = UserImages.query.filter_by(user_auth_id=user.id).all()

    return jsonify({
        "auth": {
            "user_id": user.id,
            "email": getattr(user, "email", None)
        },
        "profile": {
            "firstname": profile.firstname,
            "lastname": profile.lastname,
            "gender": profile.gender,
            "email": profile.email,
            "age": profile.age,
            "phone_number": profile.phone_number,
            "sect": profile.sect,
            "lookingfor": profile.lookingfor,
        },
        "info": {
            "hobbies": info.hobbies if info else [],
            "preferences": info.preferences if info else [],
            "bio": info.bio if info else None,
            "alcoholstatus": info.alcoholstatus if info else None,
            "childrenstatus": info.childrenstatus if info else None,
            "maritalstatus": info.maritalstatus if info else None,
            "smokestatus": info.smokestatus if info else None,
            "halalfood": info.halalfood if info else None,
        },
        "character": {
            "muslimstatus": character.muslimstatus if character else None,
            "practicing": character.practicing if character else None,
            "nationality": character.nationality if character else None,
            "personality_type": character.personality_type if character else None,
        },
        "images": [
            {"id": img.id, "imageString": img.imageString} for img in images
        ]
    }), 200


# Fetch loggedinusers info -> End


# USERPROFILE -> Start

@app.route('/userProfile', methods=['POST'])
def postUserProfileData():
    user = get_current_user_from_token()
    if not user:
        return jsonify({'error': 'Unauthorized'}), 401

    data = request.get_json()

    profile = UserProfile.query.filter_by(user_auth_id=user.id).first()
    if not profile:
        profile = UserProfile(user_auth_id=user.id)
        db.session.add(profile)

    profile.firstname = data.get('firstname')
    profile.lastname = data.get('lastname')
    profile.gender = data.get('gender')
    profile.email = data.get('email')  # optional, backend can rely on user.email
    profile.phone_number = data.get('phone_number')
    profile.age = data.get('age')
    profile.sect = data.get('sect')
    profile.lookingfor = data.get('lookingfor')

    db.session.commit()
    return jsonify({'message': 'Profile saved'}), 200


@app.route('/userProfile', methods=['GET'])
def getUserProfileData():
    try:
        profiles = UserProfile.query.all()
        users = []

        for profile in profiles:
            # Access the UserImages via Task relationship
            task_user = profile.user  # Task object
            user_images = getattr(task_user, 'user_image', [])  # list of UserImages
            user_image = user_images[0] if user_images else None

            # Construct image URL if available
            if user_image and getattr(user_image, 'imageString', None):
                image_url = request.host_url.rstrip('/') + '/uploads/' + user_image.imageString
            else:
                image_url = None

            user_data = {
                'id': profile.user_auth_id,
                'firstname': profile.firstname,
                'lastname': profile.lastname,
                'gender': profile.gender,
                'email': profile.email,
                'phone_number': profile.phone_number,
                'age': profile.age,
                'sect': profile.sect,
                'lookingfor': profile.lookingfor,            
                'image_url': image_url,
                'current_server_time': get_unix_timestamp(datetime.now(timezone.utc)),
            }
            users.append(user_data)

        return jsonify({'users': users}), 200

    except Exception as e:
        return jsonify({'error': f'Internal Server Error: {e}'}), 500

# USERPROFILE -> End

# USERINFO -> Start

@app.route('/userInfo', methods=['POST'])
def postUserInfo():
    try:
        print("📥 /userInfo called")

        # --- Auth ---
        user = get_current_user_from_token()
        if not user:
            print("⛔ Unauthorized: invalid or missing token")
            return jsonify({'error': 'Unauthorized'}), 401

        print(f"✅ Authenticated user_id={user.id}")

        # --- Profile ---
        profile = UserProfile.query.filter_by(user_auth_id=user.id).first()
        if not profile:
            print(f"❌ No UserProfile found for user_id={user.id}")
            return jsonify({'error': 'UserProfile not found'}), 404

        print(f"📄 UserProfile found: profile_id={profile.id}")

        # --- Request body ---
        data = request.get_json()
        if not data:
            print("⚠️ Empty JSON body received")
            return jsonify({'error': 'Invalid JSON'}), 400

        print(f"📦 Payload received: {data}")

        # --- UserInfo ---
        prefs = profile.info
        if not prefs:
            print("➕ Creating new UserInfo record")
            prefs = UserInfo(profile=profile)
            db.session.add(prefs)
            message = "Created user info"
        else:
            print(f"✏️ Updating UserInfo id={prefs.id}")
            message = "Updated user info"

        # --- Assign fields ---
        prefs.hobbies = data.get('hobbies', [])
        prefs.preferences = data.get('preferences', [])
        prefs.bio = data.get('bio')
        prefs.alcoholstatus = data.get('alcoholstatus')
        prefs.childrenstatus = data.get('childrenstatus')
        prefs.maritalstatus = data.get('maritalstatus')
        prefs.smokestatus = data.get('smokestatus')
        prefs.halalfood = data.get('halalfood')

        print("💾 Committing changes to DB")
        db.session.commit()

        print("✅ /userInfo completed successfully")
        return jsonify({'message': message}), 200

    except Exception as e:
        db.session.rollback()
        print("🔥 ERROR in /userInfo")
        print(str(e))
        import traceback
        traceback.print_exc()

        return jsonify({'error': 'Internal Server Error'}), 500


# get ALL users preferences
@app.route('/userInfo', methods=['GET'])
def getUserInfo():
    try:
        all_prefs = UserInfo.query.all()
        result = []

        for prefs in all_prefs:
            profile = prefs.profile
            user_data = {
                'user_profile_id': profile.id,
                'firstname': profile.firstname,
                'lastname': profile.lastname,
                'hobbies': prefs.hobbies,
                'preferences': prefs.preferences,
                'bio': prefs.bio,
                'alcoholstatus': prefs.alcoholstatus,
                'childrenstatus': prefs.childrenstatus,
                'maritalstatus': prefs.maritalstatus,
                'smokestatus': prefs.smokestatus,
                'halalfood': prefs.halalfood
            }
            result.append(user_data)

        return jsonify({'user_info': result}), 200

    except Exception as e:
        return jsonify({'error': f'Internal Server Error: {e}'}), 500

# get SINGLE users preferences

@app.route('/userInfo/<int:user_profile_id>', methods=['GET'])
def getUserInfoById(user_profile_id):
    try:
        prefs = UserInfo.query.filter_by(user_profile_id=user_profile_id).first()
        if not prefs:
            return jsonify({'error': 'UserInfo not found'}), 404

        profile = prefs.profile
        user_data = {
            'user_profile_id': profile.id,
            'firstname': profile.firstname,
            'lastname': profile.lastname,
            'hobbies': prefs.hobbies,
            'preferences': prefs.preferences,
            'bio': prefs.bio,
            'alcoholstatus': prefs.alcoholstatus,
            'childrenstatus': prefs.childrenstatus,
            'maritalstatus': prefs.maritalstatus,
            'smokestatus': prefs.smokestatus,
            'halalfood': prefs.halalfood
        }
        return jsonify({'user_info': user_data}), 200

    except Exception as e:
        return jsonify({'error': f'Internal Server Error: {e}'}), 500

# USERPREFERENCES -> End

# USERCHARACTER -> Start

@app.route('/userCharacter', methods=['POST'])
def postUserCharacter():
    try:
        user = get_current_user_from_token()
        if not user:
            return jsonify({'error': 'Unauthorized'}), 401

        profile = UserProfile.query.filter_by(user_auth_id=user.id).first()
        if not profile:
            return jsonify({'error': 'UserProfile not found'}), 404

        data = request.get_json()

        character = profile.character
        if not character:
            character = UserCharacter(profile=profile)
            db.session.add(character)

        character.muslimstatus = data.get('muslimstatus')
        character.practicing = data.get('practicing')
        character.nationality = data.get('nationality')
        character.personality_type = data.get('personality_type')

        db.session.commit()
        return jsonify({'message': 'User character saved'}), 200

    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500


# get ALL users character
@app.route('/userCharacter', methods=['GET'])
def getUserCharacter():
    try:
        all_chars = UserCharacter.query.all()
        result = []

        for char in all_chars:
            profile = char.profile
            char_data = {
                'user_profile_id': profile.id,
                'firstname': profile.firstname,
                'lastname': profile.lastname,
                'muslimstatus': char.muslimstatus,
                'practicing': char.practicing,
                'nationality': char.nationality,
                'personality_type': char.personality_type
            }
            result.append(char_data)

        return jsonify({'user_characters': result}), 200

    except Exception as e:
        return jsonify({'error': f'Internal Server Error: {e}'}), 500
    
# get SINGLE users character
@app.route('/userCharacter/<int:user_profile_id>', methods=['GET'])
def getUserCharacterById(user_profile_id):
    try:
        character = UserCharacter.query.filter_by(user_profile_id=user_profile_id).first()
        if not character:
            return jsonify({'error': 'UserCharacter not found'}), 404

        profile = character.profile
        char_data = {
            'user_profile_id': profile.id,
            'firstname': profile.firstname,
            'lastname': profile.lastname,
            'muslimstatus': character.muslimstatus,
            'practicing': character.practicing,
            'nationality': character.nationality,
            'personality_type': character.personality_type
        }

        return jsonify({'user_character': char_data}), 200

    except Exception as e:
        return jsonify({'error': f'Internal Server Error: {e}'}), 500


# USERCHARACTER -> End

# IMAGE UPLOAD AND RETRIEVAL -> Start

@app.route('/upload_image', methods=['POST'])
def upload_image():
    try:
        # Check if the request contains a file
        if 'image' not in request.files:
            return jsonify({"error": "No image file provided"}), 400

        file = request.files['image']
        new_email = request.form.get('email')

        # Check if email is provided
        if not new_email:
            return jsonify({"error": "Email is required"}), 400

        user = User.query.filter_by(email=new_email).first()

        if not user:
            return jsonify({'error': "No user registered with this email"}), 400

        user_auth_id = user.id

        # Check if the file is allowed
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)

            # Save the file in the 'uploads' folder
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(file_path)

            # Check if an image already exists for this user
            user_image = UserImages.query.filter_by(user_auth_id=user_auth_id).first()

            if user_image:
                # Update existing image
                user_image.imageString = filename
                message = "Updated user image"
            else:
                # Add new image
                user_image = UserImages(
                    user_auth_id=user_auth_id,
                    email=new_email,
                    imageString=filename
                )
                db.session.add(user_image)
                message = "Added new user image"

            db.session.commit()

            # Generate the image URL
            image_url = request.host_url + 'uploads/' + filename
            return jsonify({"message": message, "image_url": image_url}), 201

        else:
            return jsonify({"error": "Invalid image format"}), 400

    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

@app.route('/get_image/<int:user_auth_id>', methods=['GET'])
def get_image(user_auth_id):
    # Query the database for a single record matching the user_auth_id
    user_image = UserImages.query.filter_by(user_auth_id=user_auth_id).first()

    if user_image:
        # Return the image as an object
        return jsonify({
            "id": user_image.id,
            "email": user_image.email,
            "user_auth_id": user_image.user_auth_id,
            "imageString": user_image.imageString
        }), 200
    else:
        return jsonify({"error": "No image found for the given user_auth_id"}), 404
    
# IMAGE UPLOAD AND RETRIEVAL -> End

# LOCATIONINFO -> Start

@app.route('/locationInfo', methods=['POST'])
def postLocationInfo():
    try:
        data = request.get_json()
        print("POST /locationInfo received:", data)

        # ===== CATEGORY =====
        category_name = data.get("event_category")
        if not category_name:
            return jsonify({"error": "event_category is required"}), 400

        try:
            category = EventCategory.query.filter_by(name=category_name).first()
            if not category:
                category = EventCategory(name=category_name)
                db.session.add(category)
                db.session.commit()
            print("Category OK:", category.name)
        except SQLAlchemyError as e:
            print("Error processing category:", e)
            traceback.print_exc()
            db.session.rollback()
            return jsonify({"error": "Category processing failed"}), 500

        # ===== HOST =====
        host_id = data.get("event_host_id")
        if host_id is None:
            return jsonify({"error": "event_host_id is required"}), 400

        try:
            host = EventHost.query.get(host_id)
            if not host:
                return jsonify({"error": "Invalid event_host_id"}), 400
            print("Host OK:", host.id)
        except SQLAlchemyError as e:
            print("Error processing host:", e)
            traceback.print_exc()
            return jsonify({"error": "Host processing failed"}), 500

        # ===== OTHER FIELDS =====
        try:

            lat = data.get('lat')
            lng = data.get('lng')
            totalPrice = data.get('totalPrice')
            maxAttendees = data.get('maxAttendees')
            date = data.get('date')
            time = data.get('time')
            location = data.get('location')
            description = data.get('description')
            location = data.get('location')

            newLocationDetails = LocationInfo(
                maxAttendees=maxAttendees,
                maleAttendees=0,
                femaleAttendees=0,
                date=date,
                time=time,
                location=location,
                lat=lat,
                lng=lng,
                totalPrice=totalPrice,
                description=description,
                event_category_id=category.id,
                event_host_id=host.id,
                matchmake=bool(data.get("matchmake", False))
            )

            db.session.add(newLocationDetails)
            db.session.commit()
            print("Location added:", newLocationDetails.id)

        except (TypeError, ValueError) as e:
            print("Invalid input type:", e)
            traceback.print_exc()
            db.session.rollback()
            return jsonify({"error": "Invalid input types"}), 400
        except SQLAlchemyError as e:
            print("Error creating LocationInfo:", e)
            traceback.print_exc()
            db.session.rollback()
            return jsonify({"error": "Failed to add location"}), 500

        return jsonify({'message': "New Location added", "id": newLocationDetails.id}), 201

    except Exception as e:
        print("Unexpected error in /locationInfo:", e)
        traceback.print_exc()
        return jsonify({"error": "Internal server error"}), 500


@app.route('/locationInfo', methods=['GET'])
def getLocationInfo():
    locationInfo = LocationInfo.query.all()
    data = [
        {
            'id': userloc.id,
            'maxAttendees': userloc.maxAttendees,
            'maleAttendees': userloc.maleAttendees,
            'femaleAttendees': userloc.femaleAttendees,
            'date': userloc.date,
            'time': userloc.time,
            'location': userloc.location,
            'lat': userloc.lat,
            'lng': userloc.lng,
            'totalPrice': userloc.totalPrice,
            'description': userloc.description,  # NEW
            'matchmake': userloc.matchmake,      # NEW
            'event_category': userloc.event_category.name if userloc.event_category else None,
            'event_category_id': userloc.event_category_id,
            'event_host': userloc.event_host.name if hasattr(userloc, 'event_host') and userloc.event_host else None,  # NEW
            'event_host_id': userloc.event_host_id if hasattr(userloc, 'event_host_id') else None,  # NEW
            'current_round': userloc.current_round
        }
        for userloc in locationInfo
    ]
    return jsonify(data)

# LOCATIONINFO -> End

# TICKETS -> Start

@app.route('/my_tickets', methods=['GET'])
def get_user_tickets():
    user_id = request.args.get('user_id')

    if not user_id:
        return jsonify({'message': 'user_id is required'}), 400

    attendances = Attendance.query.filter_by(user_id=user_id).all()
    tickets = []

    for attendance in attendances:
        location = LocationInfo.query.get(attendance.location_id)
        if not location:
            continue

        checked_in = has_user_checked_in(user_id, location.id)

        tickets.append({
            'location_id': location.id,
            'event_category': location.event_category.name if location.event_category else None,
            'event_category_id': location.event_category_id,
            'event_host': location.event_host.name if location.event_host else None,  # NEW
            'event_host_id': location.event_host_id,
            'description': location.description,  # NEW
            'matchmake': location.matchmake,      # NEW
            'date': location.date,
            'time': location.time,
            'location': location.location,
            'checked_in': checked_in,
            'maleAttendees': location.maleAttendees or 0,
            'femaleAttendees': location.femaleAttendees or 0,
            'maxAttendees': location.maxAttendees or 0
        })

    return jsonify({'tickets': tickets}), 200

# TICKETS -> End

# CHECK-IN AND ATTENDANCE -> Start

# ✅ Route: Perform check-in
@app.route('/checkin', methods=['POST'])
def checkin():
    data = request.get_json()
    user_id = data.get('user_id')
    location_id = data.get('location_id')

    if not user_id or not location_id:
        return jsonify({'message': 'user_id and location_id are required'}), 400

    # Validate location
    user = User.query.get(user_id)
    location = LocationInfo.query.get(location_id)
    if not user or not location:
        return jsonify({'message': 'Invalid location or Id'}), 404

    # User must have marked attendance first
    attendance = Attendance.query.filter_by(user_id=user_id, location_id=location_id).first()
    if not attendance:
        return jsonify({'message': 'User must attend before check-in'}), 403

    # Check if already checked in
    existing_checkin = CheckIn.query.filter_by(user_id=user_id, location_id=location_id).first()
    if existing_checkin:
        return jsonify({'message': 'User already checked in'}), 400

    # Validate if check-in already closed for this location # Work: 41410282
    if location.checkin_closed:  # Work: 41410282
        return jsonify({'message': 'Check-in is closed for this event'}), 400  # Work: 41410282

    # Slot Limit Enforcement
    checkin_count = CheckIn.query.filter_by(location_id=location_id).count()
    if checkin_count >= location.maxAttendees and not location.checkin_closed:  # Checks for the limit and if checkin is not closed to avoid duplicate matches
        location.checkin_closed = True  # Work: 41410282
        db.session.commit()  # Work: 41410282
        trigger_matchmaking_for_location(location_id)  # Work: 41410282
        return jsonify({'message': f'All {location.maxAttendees} slots are filled'}), 400

    # Time-Based Restrictions (10 minutes after event time)
    try:
        event_time = datetime.strptime(f"{location.date} {location.time}", "%Y-%m-%d %H:%M")
        current_time = datetime.now()
        time_diff = (current_time - event_time).total_seconds()

        if time_diff > 600:
            location.checkin_closed = True  # Work: 41410282
            db.session.commit()  # Work: 41410282
            # Trigger matchmaking when time expires (even if slots aren't full)
            trigger_matchmaking_for_location(location_id)
            return jsonify({'message': 'Check-in period has ended (10 minutes after event time)'}), 400
    except Exception as e:
        print(f"Error parsing event time: {str(e)}")

    # Create check-in
    new_checkin = CheckIn(user_id=user_id, location_id=location_id)
    db.session.add(new_checkin)
    db.session.commit()

    # Check if this check-in completes the slots or triggers end phase
    updated_checkin_count = CheckIn.query.filter_by(location_id=location_id).count()
    if updated_checkin_count >= location.maxAttendees:
        location.checkin_closed = True  # Work: 41410282
        db.session.commit()  # Work: 41410282
        # All slots filled - trigger automatic matchmaking
        trigger_matchmaking_for_location(location_id)

    return jsonify({
        'message': 'Check-in successful',
        'user_id': user_id,
        'location_id': location_id,
        'timestamp': new_checkin.timestamp.isoformat(),
        'checkin_status': f"{updated_checkin_count}/{location.maxAttendees} checked in"
    }), 200


@app.route('/checkin', methods=['GET'])
def check_checkin():
    user_id = request.args.get('user_id')
    location_id = request.args.get('location_id')

    if not user_id or not location_id:
        return jsonify({'message': 'Missing user_id or location_id'}), 400

    checkin = CheckIn.query.filter_by(user_id=user_id, location_id=location_id).first()

    if checkin:
        location = checkin.location

        # Count total check-ins at this location
        checkin_count = CheckIn.query.filter_by(location_id=location_id).count()
        max_attendees = location.maxAttendees

    if checkin:
        location = checkin.location
        return jsonify({
            'checked_in': True,
            'timestamp': checkin.timestamp,
            'checkin_status': f"{checkin_count}/{max_attendees} checked in",
            'location': {
                'id': location.id,
                'location': location.location,
                'date': location.date,
                'time': location.time,
                'lat': location.lat,
                'lng': location.lng,
                'event_type': location.event_type,
                'maxAttendees': location.maxAttendees,
                'maleAttendees': location.maleAttendees,
                'femaleAttendees': location.femaleAttendees,
                'totalPrice': location.totalPrice
            }
        }), 200
    else:
        return jsonify({'checked_in': False}), 200


@app.route('/attend', methods=['POST'])
def attend_location():
    data = request.get_json()
    user_id = data.get('user_id')
    location_id = data.get('location_id')

    if not user_id or not location_id:
        return jsonify({'message': 'Missing user_id or location_id'}), 400

    user = User.query.get(user_id)
    location = LocationInfo.query.get(location_id)
    profile = UserProfile.query.filter_by(user_auth_id=user_id).first()

    if not user or not location:
        return jsonify({'message': 'Invalid user or location'}), 404

    if not profile or not profile.gender:
        return jsonify({'message': 'User profile or gender not set'}), 400

    if Attendance.query.filter_by(user_id=user_id, location_id=location_id).first():
        return jsonify({'message': 'User already marked as attending'}), 400

    # ✅ Mark attendance with hasAttended = True
    attendance = Attendance(user_id=user_id, location_id=location_id, hasAttended=True)
    db.session.add(attendance)

    # Update gender-based counts
    gender = profile.gender.lower()
    if gender.lower() in ['men', 'man', 'male']:
        location.maleAttendees = (location.maleAttendees or 0) + 1
    elif gender.lower() in ['women', 'woman', 'female']:
        location.femaleAttendees = (location.femaleAttendees or 0) + 1

    db.session.commit()

    return jsonify({'message': 'User marked as attending and counts updated'}), 200


@app.route('/attend', methods=['GET'])
def get_attendance():
    location_id = request.args.get('location_id')
    if not location_id:
        return jsonify({'message': 'location_id is required'}), 400

    location = LocationInfo.query.get(location_id)
    if not location:
        return jsonify({'message': 'Location not found'}), 404

    attendances = Attendance.query.filter_by(location_id=location.id).all()

    attendee_list = []
    for attendance in attendances:
        user = User.query.get(attendance.user_id)
        profile = getattr(user, 'user_data', None)
        checked_in = CheckIn.query.filter_by(user_id=user.id, location_id=location.id).first() is not None

        attendee_list.append({
            'user_id': user.id,
            'email': user.email,
            'gender': profile.gender if profile else None,
            'attending_at': attendance.timestamp.strftime('%Y-%m-%d %H:%M:%S'),
            'checked_in': checked_in,
            'hasAttended': attendance.hasAttended
        })

    total_attendees = (location.maleAttendees or 0) + (location.femaleAttendees or 0)

    return jsonify({
        'location': location.location,
        'date': location.date,
        'time': location.time,
        'maleAttendees': location.maleAttendees or 0,
        'femaleAttendees': location.femaleAttendees or 0,
        'totalAttendees': total_attendees,
        'maxAttendees': location.maxAttendees or 0,
        'attendees': attendee_list
    }), 200


@app.route('/attendances/<int:user_id>/<int:location_id>', methods=['GET'])
def get_user_attendance_for_location(user_id, location_id):
    record = Attendance.query.filter_by(user_id=user_id, location_id=location_id).first()
    return jsonify({'hasAttended': record.hasAttended if record else False})

# CHECK-IN AND ATTENDANCE -> End

# MATCHES FOR LOCATION -> Start

@app.route('/matches_at_location/<int:user_id>/<int:location_id>', methods=['GET'])
def get_user_matches_for_location(user_id, location_id):
    try:
        create_new_matches = request.args.get('create_new_matches')

        if create_new_matches and create_new_matches == 'true':
            match_making_result = trigger_matchmaking_for_location(location_id)
            print(f"Match making at location result: {match_making_result}")

        # Query to get all existing active matches for a given user at a specific location
        existing_matches = (
            db.session.query(Match)
            .join(CheckIn, or_(
                CheckIn.user_id == Match.user1_id,
                CheckIn.user_id == Match.user2_id
            ))
            .filter(
                or_(Match.user1_id == user_id, Match.user2_id == user_id),
                Match.status == 'active',
                Match.location_id == location_id
            )
            .order_by(desc(Match.visible_after))
            .all()
        )

        if len(existing_matches) == 0:
            return jsonify({'message': 'No matches left for this event'}), 400

        preferences = (UserPreference.query
                       .filter(
                            or_(UserPreference.user_id == user_id, UserPreference.preferred_user_id == user_id)
                       ).all())

        preference_pairs = set()
        for pref in preferences:
            preference_pairs.add((pref.user_id, pref.preferred_user_id))
            preference_pairs.add((pref.preferred_user_id, pref.user_id)) # Add reverse pair also

        # Format results with matches
        result = []
        for match in existing_matches:

            matched_user_id = int(
                match.user2_id if match.user1_id == user_id else match.user1_id)  # get opposite match id

            # Checking if this match already has a preference available
            if (user_id, matched_user_id) in preference_pairs:
                print(f"SKIPPING: Existing preference found")
                continue

            # Get user image if available
            user_image = UserImages.query.filter_by(user_auth_id=matched_user_id).first()
            image_url = None
            if user_image and user_image.imageString:
                image_url = f"/uploads/{user_image.imageString}"

            other_user_data = UserProfile.query.filter_by(user_auth_id=matched_user_id).first()

            result.append({
                'user_id': matched_user_id,
                'email': other_user_data.email,
                'firstname': other_user_data.firstname,
                'lastname': other_user_data.lastname,
                'preferences': other_user_data.preferences,
                'age': other_user_data.age,
                'bio': other_user_data.bio,
                'hobbies': other_user_data.hobbies,
                'gender': other_user_data.gender,
                'phone_number': other_user_data.phone_number,
                'image_url': image_url,
                'status': match.status,
                'location': match.location_id,
                'current_server_time': get_unix_timestamp(datetime.now(timezone.utc)),
                'visible_after': match.visible_after
            })

        if len(result) == 0:
            return jsonify({'message': 'No matches left for this event'}), 400

        return jsonify({'matches': result})

    except Exception as e:
        print(f"Error in get_user_matches: {str(e)}")
        return jsonify({'matches': []})

# MATCHES FOR LOCATION -> End

# PREFERENCE HANDLING -> Start

@app.route('/preference', methods=['POST'])
def set_preference():
    try:
        data = request.get_json()
        user_email = data.get('user_email')
        preferred_user_email = data.get('preferred_user_email')
        preference = data.get('preference')  # 'like', 'reject', 'save_later'

        # Validate inputs
        if not user_email or not preferred_user_email or not preference:
            return jsonify({'error': 'Missing required fields'}), 400

        if preference not in ['like', 'reject', 'save_later']:
            return jsonify({'error': 'Invalid preference type'}), 400

        # Get user IDs from emails
        user = User.query.filter_by(email=user_email).first()
        preferred_user = User.query.filter_by(email=preferred_user_email).first()

        if not user or not preferred_user:
            return jsonify({'error': 'One or both users not found'}), 404

        # Check if preference already exists
        existing_preference = UserPreference.query.filter_by(
            user_id=user.id,
            preferred_user_id=preferred_user.id
        ).first()

        if existing_preference:
            # Update existing preference
            existing_preference.preference = preference
            existing_preference.timestamp = datetime.now(timezone.utc)
        else:
            # Create new preference
            new_preference = UserPreference(
                user_id=user.id,
                preferred_user_id=preferred_user.id,
                preference=preference
            )
            db.session.add(new_preference)

        if preference == 'reject':
            user1_id = user.id
            user2_id = preferred_user.id

            # Check if there's an existing match
            existing_match = Match.query.filter(
                or_(
                    and_(Match.user1_id == user1_id, Match.user2_id == user2_id),
                    and_(Match.user1_id == user2_id, Match.user2_id == user1_id)
                )
            ).first()

            # Case II: One or both users rejected
            if existing_match:
                # Mark match as deleted
                existing_match.status = 'deleted'

        # Check if this creates a match
        process_potential_match(user.id, preferred_user.id)

        db.session.commit()

        return jsonify({'message': f'Preference set to {preference}'}), 201

    except Exception as e:
        print(f"Error in set_preference: {str(e)}")
        return jsonify({'error': 'Internal Server Error'}), 500


@app.route('/matches/<email>', methods=['GET'])
def get_user_matches(email):
    try:
        user = User.query.filter_by(email=email).first()
        if not user:
            return jsonify({'error': 'User not found'}), 404

        # Get all matches for this user that are visible now
        current_time = datetime.now(timezone.utc)
        matches = Match.query.filter(
            or_(
                Match.user1_id == user.id,
                Match.user2_id == user.id
            ),
            Match.status != 'deleted',
            Match.visible_after <= get_unix_timestamp(current_time)
        ).all()

        # Format the response
        result = []
        for match in matches:
            # Determine the other user ID
            other_user_id = match.user2_id if match.user1_id == user.id else match.user1_id
            other_user = User.query.get(other_user_id)
            other_user_data = UserProfile.query.filter_by(user_auth_id=other_user_id).first()

            if not other_user or not other_user_data:
                continue

            # Get user preferences
            user_pref = UserPreference.query.filter_by(
                user_id=user.id, preferred_user_id=other_user_id
            ).first()

            other_pref = UserPreference.query.filter_by(
                user_id=other_user_id, preferred_user_id=user.id
            ).first()

            # Determine match status from user's perspective
            if match.status == 'active':
                # Both liked each other
                display_status = 'matched'
                show_message_button = True
            else:  # status is 'pending'
                if user_pref and user_pref.preference == 'save_later':
                    display_status = 'decide'  # User needs to decide
                    show_message_button = False
                elif other_pref and other_pref.preference == 'save_later':
                    display_status = 'pending'  # Waiting for other user
                    show_message_button = False
                else:
                    display_status = 'pending'  # Generic pending
                    show_message_button = False

            # Get profile image
            user_image = UserImages.query.filter_by(user_auth_id=other_user_id).first()
            image_url = None
            if user_image and user_image.imageString:
                image_url = request.host_url + 'uploads/' + user_image.imageString

            # Add match to result
            result.append({
                'match_id': match.id,
                'user_id': other_user_id,
                'firstname': other_user_data.firstname,
                'email': other_user.email,
                'age': other_user_data.age,
                'bio': other_user_data.bio,
                'status': display_status,
                'show_message_button': show_message_button,
                'match_date': match.match_date,
                'image_url': image_url
            })

        return jsonify({'matches': result}), 200

    except Exception as e:
        print(f"Error in get_user_matches: {str(e)}")
        return jsonify({'error': 'Internal Server Error'}), 500


# Only for users that are saved for later and waiting a decision (accept or reject) inside Matches screen on frontend -> Post their decision
@app.route('/update_match_status', methods=['POST'])
def update_match_status():
    try:
        data = request.get_json()
        match_id = data.get('match_id')
        user_email = data.get('user_email')
        decision = data.get('decision')  # 'accept' or 'reject'

        # Validate inputs
        if not match_id or not user_email or not decision:
            return jsonify({'error': 'Missing required fields'}), 400

        if decision not in ['accept', 'reject']:
            return jsonify({'error': 'Invalid decision'}), 400

        # Get user
        user = User.query.filter_by(email=user_email).first()
        if not user:
            return jsonify({'error': 'User not found'}), 404

        # Get match
        match = Match.query.get(match_id)
        if not match:
            return jsonify({'error': 'Match not found'}), 404

        # Verify user is part of this match
        if match.user1_id != user.id and match.user2_id != user.id:
            return jsonify({'error': 'User not authorized to update this match'}), 403

        # Determine other user ID
        other_user_id = match.user2_id if match.user1_id == user.id else match.user1_id

        # Update user preference based on decision
        if decision == 'accept':
            pref = UserPreference.query.filter_by(
                user_id=user.id, preferred_user_id=other_user_id
            ).first()

            if pref:
                pref.preference = 'like'
            else:
                new_pref = UserPreference(
                    user_id=user.id,
                    preferred_user_id=other_user_id,
                    preference='like'
                )
                db.session.add(new_pref)

            # Check if this creates a match
            process_potential_match(user.id, other_user_id)

        else:  # decision == 'reject'
            pref = UserPreference.query.filter_by(
                user_id=user.id, preferred_user_id=other_user_id
            ).first()

            if pref:
                pref.preference = 'reject'
            else:
                new_pref = UserPreference(
                    user_id=user.id,
                    preferred_user_id=other_user_id,
                    preference='reject'
                )
                db.session.add(new_pref)

            # Mark match as deleted
            match.status = 'deleted'

        db.session.commit()

        return jsonify({'message': f'Match {decision}ed successfully'}), 200

    except Exception as e:
        print(f"Error in update_match_status: {str(e)}")
        return jsonify({'error': 'Internal Server Error'}), 500

# PREFERENCE HANDLING -> End

# MATCHMAKING LOGIC UTILITIES -> Start

# Given a user id returns the best 5 matches sorted
@app.route('/match/<int:user_id>', methods=['GET'])
def get_matches_endpoint(user_id):
    matches = get_user_matches(user_id)
    return jsonify({
        'user_id': user_id,
        'matches': matches
    })


# Get all users best matches
@app.route('/matches', methods=['GET'])
def get_all_matches():
    matches = match_all_users()
    return jsonify({'matches': matches})


# MATCHMAKING LOGIC UTILITIES -> End


# CHAT FUNCTIONALITY -> Start

@app.route('/send_message', methods=['POST'])
def send_message():
    sender_email = request.form.get('sender_email')
    receiver_email = request.form.get('receiver_email')
    message = request.form.get('message')

    # Check if any of the fields are missing
    if not sender_email or not receiver_email or not message:
        return jsonify({'error': 'Missing data'}), 400

    # Look up user IDs based on emails
    sender = User.query.filter_by(email=sender_email).first()
    receiver = User.query.filter_by(email=receiver_email).first()

    if not sender or not receiver:
        return jsonify({'error': 'Sender or receiver not found'}), 404

    # Store the message in the database
    new_message = Message(sender_id=sender.id, receiver_id=receiver.id, message=message)
    db.session.add(new_message)
    db.session.commit()

    # Emit the message to the receiver's room using receiver's email
    socketio.emit('receive_message', {
        'sender_email': sender_email,
        'receiver_email': receiver_email,
        'message': message
    }, room=receiver_email)

    return jsonify({'status': 'Message sent'})


@socketio.on('send_message')
def handle_message(data):
    sender_email = data['sender_email']
    receiver_email = data['receiver_email']
    message = data['message']

    # Look up user IDs based on emails
    sender = User.query.filter_by(email=sender_email).first()
    receiver = User.query.filter_by(email=receiver_email).first()

    if not sender or not receiver:
        emit('error', {'error': 'Sender or receiver not found'})
        return

    # Store the message in the database
    new_message = Message(sender_id=sender.id, receiver_id=receiver.id, message=message)
    db.session.add(new_message)
    db.session.commit()

    # Emit the message to the receiver's room using receiver's email
    emit('receive_message', {
        'sender_email': sender_email,
        'receiver_email': receiver_email,
        'message': message
    }, room=receiver_email)


@socketio.on('join')
def on_join(data):
    user_email = data['user_email']
    user = User.query.filter_by(email=user_email).first()

    if not user:
        emit('error', {'error': 'User not found'})
        return

    join_room(user_email)  # Join the room based on email
    emit('status', {'msg': f'User {user_email} has entered the room.'}, room=user_email)


@app.route('/get_chats', methods=['GET'])
def get_chats():
    email1 = request.args.get('email1')
    email2 = request.args.get('email2')

    if not email1 or not email2:
        return jsonify({'error': 'Missing email addresses'}), 400

    # Retrieve user IDs based on the provided emails
    user1 = User.query.filter_by(email=email1).first()
    user2 = User.query.filter_by(email=email2).first()

    if not user1 or not user2:
        return jsonify({'error': 'One or both users not found'}), 404

    # Fetch the chat history between the two users
    messages = Message.query.filter(
        ((Message.sender_id == user1.id) & (Message.receiver_id == user2.id)) |
        ((Message.sender_id == user2.id) & (Message.receiver_id == user1.id))
    ).order_by(Message.timestamp).all()

    # Prepare the chat history for response, adding sender and receiver emails
    chat_history = [
        {
            'sender_id': msg.sender_id,
            'sender_email': user1.email if msg.sender_id == user1.id else user2.email,
            'receiver_id': msg.receiver_id,
            'receiver_email': user2.email if msg.receiver_id == user2.id else user1.email,
            'message': msg.message,
            'timestamp': msg.timestamp
        }
        for msg in messages
    ]

    return jsonify(chat_history)

# CHAT FUNCTIONALITY -> End

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080)