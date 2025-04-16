from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity
from app.models import Device, User
from app import db

devices_bp = Blueprint('devices', __name__)

@devices_bp.route('/devices', methods=['GET'])
@jwt_required()
def get_devices():
    """Get all devices for the current user"""
    try:
        current_user_id = int(get_jwt_identity())
        user = User.query.get(current_user_id)
        
        if not user:
            return jsonify({'error': 'User not found'}), 404
            
        devices = Device.query.filter_by(user_id=current_user_id).all()
        return jsonify({
            'count': len(devices),
            'devices': [device.to_dict() for device in devices]
        }), 200
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@devices_bp.route('/devices', methods=['POST'])
@jwt_required()
def add_device():
    """Add a new device"""
    try:
        current_user_id = int(get_jwt_identity())
        data = request.get_json()
        
        # Validate required fields
        required_fields = ['name', 'ip_address', 'mac_address']
        for field in required_fields:
            if field not in data:
                return jsonify({'error': f'Missing required field: {field}'}), 400
        
        # Create new device
        device = Device(
            name=data['name'],
            ip_address=data['ip_address'],
            mac_address=data['mac_address'],
            user_id=current_user_id
        )
        
        db.session.add(device)
        db.session.commit()
        
        return jsonify({
            'message': 'Device added successfully',
            'device': device.to_dict()
        }), 201
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@devices_bp.route('/devices/<int:device_id>', methods=['PUT'])
@jwt_required()
def update_device(device_id):
    """Update a device"""
    try:
        current_user_id = int(get_jwt_identity())
        device = Device.query.get(device_id)
        
        if not device:
            return jsonify({'error': 'Device not found'}), 404
            
        if device.user_id != current_user_id:
            return jsonify({'error': 'Unauthorized'}), 403
            
        data = request.get_json()
        
        # Update fields if provided
        if 'name' in data:
            device.name = data['name']
        if 'ip_address' in data:
            device.ip_address = data['ip_address']
        if 'mac_address' in data:
            device.mac_address = data['mac_address']
            
        db.session.commit()
        
        return jsonify({
            'message': 'Device updated successfully',
            'device': device.to_dict()
        }), 200
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@devices_bp.route('/devices/<int:device_id>', methods=['DELETE'])
@jwt_required()
def delete_device(device_id):
    """Delete a device"""
    try:
        current_user_id = int(get_jwt_identity())
        device = Device.query.get(device_id)
        
        if not device:
            return jsonify({'error': 'Device not found'}), 404
            
        if device.user_id != current_user_id:
            return jsonify({'error': 'Unauthorized'}), 403
            
        db.session.delete(device)
        db.session.commit()
        
        return jsonify({'message': 'Device deleted successfully'}), 200
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500 