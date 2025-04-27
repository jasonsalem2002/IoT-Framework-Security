from flask import Blueprint, jsonify, request
from flask_jwt_extended import jwt_required, get_jwt_identity
from app.models import NetworkTraffic, User
from app import db

network_traffic_bp = Blueprint('network_traffic', __name__)

@network_traffic_bp.route('/network-traffic', methods=['GET'])
@jwt_required()
def get_network_traffic():
    """
    Return network-traffic rows.
    Optional query string: ?limit=<positive-int> 
        Limits the number of rows returned
    """
    try:
        current_user_id = int(get_jwt_identity())
        user = User.query.get(current_user_id)
        if not user:
            return jsonify({'error': 'User not found'}), 404

        # Check if 'limit' requested (limit on number of packets)
        limit = request.args.get('limit', default=None, type=int)
        if limit is not None and limit <= 0:
            return jsonify({'error': 'limit must be a positive integer'}), 400

        query = NetworkTraffic.query.order_by(NetworkTraffic.id.desc())
        if limit:
            query = query.limit(limit)

        entries = query.all()
        entries_list = [e.to_dict() for e in entries]

        return jsonify({'count': len(entries_list), 'entries': entries_list}), 200

    except Exception as e:
        return jsonify({'error': str(e)}), 500
