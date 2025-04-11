from flask import Blueprint, request, jsonify
from flask_jwt_extended import create_access_token
from app.models import User
from app import db

auth_bp = Blueprint('auth', __name__)

@auth_bp.route('/login', methods=['POST'])
def login():
    try:
        # Debug: Print incoming request data
        print("\n=== Incoming Request ===")
        print(f"Request data: {request.get_json()}")
        
        data = request.get_json()
        if not data or not data.get('email') or not data.get('password'):
            print("Error: Missing email or password")
            return jsonify({'error': 'Email and password are required'}), 400

        user = User.query.filter_by(email=data['email']).first()
        print(f"\n=== User Lookup ===")
        print(f"Found user: {user.to_dict() if user else 'None'}")

        if user and user.check_password(data['password']):
            access_token = create_access_token(identity=str(user.id))
            response = {
                'access_token': access_token,
                'user': user.to_dict()
            }
            print("\n=== Response ===")
            print(f"Success response: {response}")
            return jsonify(response), 200
        else:
            print("\n=== Response ===")
            print("Error: Invalid credentials")
            return jsonify({'error': 'Invalid credentials'}), 401

    except Exception as e:
        print("\n=== Error ===")
        print(f"Exception occurred: {str(e)}")
        return jsonify({'error': str(e)}), 500 