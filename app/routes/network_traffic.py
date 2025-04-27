from flask import Blueprint, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity
from app.models import NetworkTraffic, Device, User
from app import db
from datetime import datetime, timedelta

network_traffic_bp = Blueprint('network_traffic', __name__)

@network_traffic_bp.route('/network-traffic', methods=['GET'])
@jwt_required()
def get_network_traffic():
    """Get all network traffic logs"""
    try:
        current_user_id = int(get_jwt_identity())
        user = User.query.get(current_user_id)
        if not user:
            return jsonify({'error': 'User not found'}), 404

        entries = NetworkTraffic.query.all()
        entries_list = [entry.to_dict() for entry in entries]

        return jsonify({
            'count': len(entries_list),
            'entries': entries_list
        }), 200

    except Exception as e:
        return jsonify({'error': str(e)}), 500


def get_user_ips(user_id):
    """Helper: Get all IP addresses of the user's devices"""
    devices = Device.query.filter_by(user_id=user_id).all()
    return [device.ip_address for device in devices]


def filter_attacks(user_ips, time_filter):
    """Helper: Filter attacks (category != normal) based on IP and time"""
    query = NetworkTraffic.query.filter(
        NetworkTraffic.category != 'normal',
        NetworkTraffic.ip_src.in_(user_ips)
    )

    if time_filter == 'today':
        today = datetime.utcnow().date()
        query = query.filter(NetworkTraffic.timestamp.startswith(today.strftime('%Y-%m-%d')))
    elif time_filter == 'week':
        today = datetime.utcnow()
        week_ago = today - timedelta(days=7)
        query = query.filter(NetworkTraffic.timestamp >= week_ago.strftime('%Y-%m-%d'))
    elif time_filter == 'month':
        today = datetime.utcnow()
        month_ago = today - timedelta(days=30)
        query = query.filter(NetworkTraffic.timestamp >= month_ago.strftime('%Y-%m-%d'))

    return query.all()


@network_traffic_bp.route('/network-traffic/attacks/today', methods=['GET'])
@jwt_required()
def get_today_attacks():
    """Get today's attacks for current user"""
    try:
        current_user_id = int(get_jwt_identity())
        user_ips = get_user_ips(current_user_id)

        attacks = filter_attacks(user_ips, 'today')
        entries_list = [attack.to_dict() for attack in attacks]

        return jsonify({
            'count': len(entries_list),
            'attacks': entries_list
        }), 200

    except Exception as e:
        return jsonify({'error': str(e)}), 500


@network_traffic_bp.route('/network-traffic/attacks/week', methods=['GET'])
@jwt_required()
def get_week_attacks():
    """Get this week's attacks for current user"""
    try:
        current_user_id = int(get_jwt_identity())
        user_ips = get_user_ips(current_user_id)

        attacks = filter_attacks(user_ips, 'week')
        entries_list = [attack.to_dict() for attack in attacks]

        return jsonify({
            'count': len(entries_list),
            'attacks': entries_list
        }), 200

    except Exception as e:
        return jsonify({'error': str(e)}), 500


@network_traffic_bp.route('/network-traffic/attacks/month', methods=['GET'])
@jwt_required()
def get_month_attacks():
    """Get this month's attacks for current user"""
    try:
        current_user_id = int(get_jwt_identity())
        user_ips = get_user_ips(current_user_id)

        attacks = filter_attacks(user_ips, 'month')
        entries_list = [attack.to_dict() for attack in attacks]

        return jsonify({
            'count': len(entries_list),
            'attacks': entries_list
        }), 200

    except Exception as e:
        return jsonify({'error': str(e)}), 500