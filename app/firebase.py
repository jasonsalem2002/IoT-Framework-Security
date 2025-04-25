import firebase_admin
from firebase_admin import credentials, messaging
from flask import Blueprint, request, jsonify

firebase_bp = Blueprint('firebase', __name__)

# Initialize Firebase
cred = credentials.Certificate("serviceAccountKey.json")
firebase_admin.initialize_app(cred)

# Store registered FCM tokens
tokens = set()

@firebase_bp.route('/register_token', methods=['POST'])
def register_token():
    """Register a new FCM token"""
    try:
        data = request.get_json()
        token = data.get('token')
        if token:
            tokens.add(token)
            return jsonify({"success": True, "message": "Token registered."}), 200
        else:
            return jsonify({"success": False, "message": "No token provided."}), 400
    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500

def send_push_to_all(title, body):
    """
    Sends a notification to all registered tokens.
    """
    if not tokens:
        print("No tokens registered, skipping push notification.")
        return

    # Send notifications to all registered tokens
    for token in tokens.copy():  # copy because we might remove invalid tokens
        message = messaging.Message(
            notification=messaging.Notification(
                title=title,
                body=body
            ),
            token=token
        )
        try:
            response = messaging.send(message)
            print(f"Sent notification to {token}. Response: {response}")
        except messaging.FirebaseError as e:
            print(f"Failed to send to {token}. Error: {str(e)}")
            # If token is invalid, remove it from the list
            tokens.remove(token)

def detect_anomaly(entry):
    """
    Check if a network traffic entry is anomalous and send notification if needed.
    """
    if entry.label == "Anomaly":
        title = "Security Alert"
        body = f"Detected {entry.category} from {entry.ip_src} to {entry.ip_dst}"
        send_push_to_all(title, body) 