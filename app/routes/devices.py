from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity
from app.models import Device, User
from app import db
import subprocess
import re
import json
import platform
import shlex

devices_bp = Blueprint('devices', __name__)

def ping_ip(ip_address):
    """
    Execute ping command and parse results
    Returns a dictionary with ping statistics (Windows-compatible)
    """
    print(f"\n====== PINGING {ip_address} ======")
    try:
        # Detect platform
        is_windows = platform.system().lower() == 'windows'

        # Choose ping command based on OS
        ping_cmd = ['ping', '-n', '5', ip_address] if is_windows else ['ping', '-c', '5', ip_address]

        process = subprocess.Popen(
            ping_cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            shell=True  # Required for Windows
        )
        stdout, stderr = process.communicate()
        
        print(f"---- PING RAW OUTPUT ----")
        print(stdout)
        print(f"--------------------------")
        
        if process.returncode != 0:
            result = {
                'status': 'offline',
                'latency': None,
                'packet_loss': '100%',
                # 'output': stderr if stderr else stdout
            }
            print(f"PING RESULT (Error): {result}")
            return result
        
        # Initialize defaults
        packet_loss = 'Unknown'
        latency = None
        
        if is_windows:
            # Windows ping output parsing
            # Packet loss (Windows: "Lost = 0 (0% loss)")
            packet_loss_match = re.search(r'Lost = \d+ \((\d+)% loss\)', stdout)
            if packet_loss_match:
                packet_loss = packet_loss_match.group(1) + '%'
            
            # Latency (Windows: "Minimum = 1ms, Maximum = 4ms, Average = 2ms")
            latency_match = re.search(r'Minimum = (\d+)ms, Maximum = (\d+)ms, Average = (\d+)ms', stdout)
            if latency_match:
                latency = {
                    'min': float(latency_match.group(1)),
                    'max': float(latency_match.group(2)),
                    'avg': float(latency_match.group(3))
                }
        else:
            # Linux/macOS ping output parsing
            # Packet loss (Linux: "20% packet loss")
            packet_loss_match = re.search(r'(\d+)% packet loss', stdout)
            if packet_loss_match:
                packet_loss = packet_loss_match.group(1) + '%'
            
            # Latency (Linux: "min/avg/max/mdev = 1.234/2.345/3.456/0.789 ms")
            latency_match = re.search(r'min/avg/max/mdev = (\d+\.\d+)/(\d+\.\d+)/(\d+\.\d+)/(\d+\.\d+)', stdout)
            if latency_match:
                latency = {
                    'min': float(latency_match.group(1)),
                    'avg': float(latency_match.group(2)),
                    'max': float(latency_match.group(3)),
                    'mdev': float(latency_match.group(4))
                }
        
        # Handle case where destination is unreachable / doesn't exist
        if latency is None:              
            packet_loss = '100%'         
            status = 'offline'
        elif packet_loss == 'Unknown':
            status = 'packet loss unknown'
        else:
            status = 'online' if float(packet_loss.rstrip('%')) < 100 else 'offline'

        
        result = {
            'status': status,
            'latency': latency,
            'packet_loss': packet_loss,
            # 'output': stdout.strip()
        }
        
        print(f"---- PARSED PING RESULT ----")
        print(f"Status: {result['status']}")
        print(f"Packet Loss: {result['packet_loss']}")
        print(f"Latency: {result['latency']}")
        print(f"----------------------------")
        
        return result
        
    except Exception as e:
        print(f"PING ERROR: {str(e)}")
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
        
        response = {
            'device': device.to_dict(),
            'ping_result': ping_result
        }
        
        print("\n====== RESPONSE SENT TO USER ======")
        print(json.dumps(response, indent=2))
        print("===================================\n")
        
        return jsonify(response), 200
        
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
            response = {
                'count': 0,
                'results': [],
                'message': 'No devices found'
            }
            print("\n====== RESPONSE SENT TO USER (NO DEVICES) ======")
            print(json.dumps(response, indent=2))
            print("===============================================\n")
            return jsonify(response), 200
        
        results = []
        for device in devices:
            ping_result = ping_ip(device.ip_address)
            results.append({
                'device': device.to_dict(),
                'ping_result': ping_result
            })
        
        response = {
            'count': len(results),
            'results': results
        }
        
        print("\n====== RESPONSE SENT TO USER (PING ALL) ======")
        print(json.dumps(response, indent=2))
        print("============================================\n")
        
        return jsonify(response), 200
        
    except Exception as e:
        error_response = {'error': str(e)}
        print("\n====== ERROR RESPONSE ======")
        print(json.dumps(error_response, indent=2))
        print("============================\n")
        return jsonify(error_response), 500

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

def scan_ports(ip_address, port_range=None):
    """
    Scan ports on a device using nmap
    Returns the scan results
    """
    print(f"\n====== SCANNING PORTS ON {ip_address} ======")
    try:
        # Default port range if none specified
        if not port_range:
            port_range = "1-1000"
            
        # Build nmap command for Windows
        # Basic scan with service detection
        nmap_cmd = ["nmap", "-sV", f"-p{port_range}", ip_address]
        
        print(f"Running nmap command: {' '.join(nmap_cmd)}")
        
        process = subprocess.Popen(
            nmap_cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            shell=True  # Required for Windows
        )
        stdout, stderr = process.communicate()
        
        print(f"---- NMAP RAW OUTPUT ----")
        print(stdout)
        print(f"--------------------------")
        
        if process.returncode != 0:
            result = {
                'status': 'error',
                'message': stderr if stderr else "Unknown error during port scan",
            }
            print(f"NMAP ERROR: {result}")
            return result
        
        # Parse the open ports from nmap output
        open_ports = []
        port_lines = re.finditer(r'(\d+)/tcp\s+(\w+)\s+(.+)', stdout)
        
        for match in port_lines:
            port = match.group(1)
            state = match.group(2)
            service = match.group(3).strip()
            
            if state.lower() == 'open':
                open_ports.append({
                    'port': int(port),
                    'service': service
                })
        
        result = {
            'status': 'success',
            'ip_address': ip_address,
            'port_range': port_range,
            'open_ports': open_ports,
            'total_open': len(open_ports)
        }
        
        print(f"---- PARSED NMAP RESULT ----")
        print(f"Status: {result['status']}")
        print(f"Total open ports: {result['total_open']}")
        print(f"Open ports: {result['open_ports']}")
        print(f"----------------------------")
        
        return result
        
    except Exception as e:
        print(f"NMAP ERROR: {str(e)}")
        return {
            'status': 'error',
            'message': str(e)
        }

@devices_bp.route('/devices/<int:device_id>/scan', methods=['GET'])
@jwt_required()
def scan_device_ports(device_id):
    """Scan ports on a specific device"""
    try:
        current_user_id = int(get_jwt_identity())
        device = Device.query.get(device_id)
        
        if not device:
            return jsonify({'error': 'Device not found'}), 404
            
        if device.user_id != current_user_id:
            return jsonify({'error': 'Unauthorized'}), 403
        
        # Get port range from query parameters
        port_range = request.args.get('port_range', '1-1000')
        
        # Scan the device
        scan_result = scan_ports(device.ip_address, port_range)
        
        response = {
            'device': device.to_dict(),
            'scan_result': scan_result
        }
        
        print("\n====== RESPONSE SENT TO USER (PORT SCAN) ======")
        print(json.dumps(response, indent=2))
        print("==============================================\n")
        
        return jsonify(response), 200
        
    except Exception as e:
        error_response = {'error': str(e)}
        print("\n====== ERROR RESPONSE ======")
        print(json.dumps(error_response, indent=2))
        print("============================\n")
        return jsonify(error_response), 500 