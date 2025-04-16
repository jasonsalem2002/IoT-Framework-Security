from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity
from app.models import Device, User
from app import db
import subprocess
import re

devices_bp = Blueprint('devices', __name__)

def ping_ip(ip_address):
    """
    Execute ping command and parse results
    Returns a dictionary with ping statistics
    """
    try:
        # Execute ping command
        process = subprocess.Popen(
            ['ping', '-c', '10', ip_address],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        stdout, stderr = process.communicate()
        
        if process.returncode != 0:
            return {
                'status': 'offline',
                'latency': None,
                'packet_loss': '100%',
                'output': stderr if stderr else stdout
            }
        
        # Parse packet loss
        packet_loss_match = re.search(r'(\d+)% packet loss', stdout)
        packet_loss = packet_loss_match.group(1) + '%' if packet_loss_match else 'Unknown'
        
        # Parse latency
        latency_match = re.search(r'min/avg/max/mdev = (\d+\.\d+)/(\d+\.\d+)/(\d+\.\d+)/(\d+\.\d+)', stdout)
        
        if latency_match:
            latency = {
                'min': float(latency_match.group(1)),
                'avg': float(latency_match.group(2)),
                'max': float(latency_match.group(3)),
                'mdev': float(latency_match.group(4))
            }
        else:
            latency = None
            
        return {
            'status': 'online' if float(packet_loss.rstrip('%')) < 100 else 'offline',
            'latency': latency,
            'packet_loss': packet_loss,
            'output': stdout.strip()
        }
        
    except Exception as e:
        return {
            'status': 'error',
            'message': str(e),
            'latency': None,
            'packet_loss': None
        }

@devices_bp.route('/devices/<int:device_id>/ping', methods=['GET'])
@jwt_required()
def ping_device(device_id):
    """Ping a specific device"""
    try:
        current_user_id = int(get_jwt_identity())
        device = Device.query.get(device_id)
        
        if not device:
            return jsonify({'error': 'Device not found'}), 404
            
        if device.user_id != current_user_id:
            return jsonify({'error': 'Unauthorized'}), 403
        
        # Ping the device
        ping_result = ping_ip(device.ip_address)
        
        return jsonify({
            'device': device.to_dict(),
            'ping_result': ping_result
        }), 200
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@devices_bp.route('/devices/ping-all', methods=['GET'])
@jwt_required()
def ping_all_devices():
    """Ping all devices for the current user"""
    try:
        current_user_id = int(get_jwt_identity())
        devices = Device.query.filter_by(user_id=current_user_id).all()
        
        if not devices:
            return jsonify({
                'count': 0,
                'results': [],
                'message': 'No devices found'
            }), 200
        
        results = []
        for device in devices:
            ping_result = ping_ip(device.ip_address)
            results.append({
                'device': device.to_dict(),
                'ping_result': ping_result
            })
        
        return jsonify({
            'count': len(results),
            'results': results
        }), 200
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

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