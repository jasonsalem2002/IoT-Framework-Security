from flask import Blueprint, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity
from app.models import NetworkTraffic, User
from app import db

network_traffic_bp = Blueprint('network_traffic', __name__)

@network_traffic_bp.route('/network-traffic', methods=['GET'])
@jwt_required()
def get_network_traffic():
    """Get all network traffic logs"""
    try:
        # Get the current user's identity from the JWT token and convert to int
        current_user_id = int(get_jwt_identity())
        
        # Verify the user exists
        user = User.query.get(current_user_id)
        if not user:
            return jsonify({'error': 'User not found'}), 404

        # Query all network traffic entries
        entries = NetworkTraffic.query.all()
        
        # Convert entries to dictionary format
        entries_list = [entry.to_dict() for entry in entries]
        
        return jsonify({
            'count': len(entries_list),
            'entries': entries_list
        }), 200
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500 