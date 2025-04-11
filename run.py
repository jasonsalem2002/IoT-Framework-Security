from app import create_app
from app.routes.auth import auth_bp
from app.routes.network_traffic import network_traffic_bp
from periodic_update import update_network_traffic, clear_network_traffic
import threading
import time

app = create_app()

# Register blueprints
app.register_blueprint(auth_bp, url_prefix='/api')
app.register_blueprint(network_traffic_bp, url_prefix='/api')

def run_periodic_updates():
    """Run periodic updates in a separate thread"""
    print("Starting periodic network traffic updates...")
    
    # Clear the table first
    clear_network_traffic()
    
    # Run the update immediately on startup
    update_network_traffic()
    
    # Keep running updates every 30 seconds
    while True:
        time.sleep(30)
        update_network_traffic()

if __name__ == '__main__':
    # Start the periodic update thread
    update_thread = threading.Thread(target=run_periodic_updates, daemon=True)
    update_thread.start()
    
    # Start the Flask application
    app.run(host='0.0.0.0', port=3000, debug=True) 