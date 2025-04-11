from app import db
from werkzeug.security import generate_password_hash, check_password_hash

class User(db.Model):
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    
    def set_password(self, password):
        self.password = generate_password_hash(password, method='pbkdf2:sha256')
        
    def check_password(self, password):
        return check_password_hash(self.password, password)
    
    def to_dict(self):
        return {
            'id': self.id,
            'email': self.email
        }

class NetworkTraffic(db.Model):
    __tablename__ = 'network_traffic'
    
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.String(50))
    ip_src = db.Column(db.String(50))
    ip_dst = db.Column(db.String(50))
    tcp_srcport = db.Column(db.Integer, nullable=True)
    tcp_dstport = db.Column(db.Integer, nullable=True)
    udp_srcport = db.Column(db.Integer, nullable=True)
    udp_dstport = db.Column(db.Integer, nullable=True)
    eth_src = db.Column(db.String(50))
    eth_dst = db.Column(db.String(50))
    category = db.Column(db.String(50))
    detected_as = db.Column(db.String(50))
    
    def to_dict(self):
        return {
            'id': self.id,
            'timestamp': self.timestamp,
            'ip_src': self.ip_src,
            'ip_dst': self.ip_dst,
            'tcp_srcport': self.tcp_srcport,
            'tcp_dstport': self.tcp_dstport,
            'udp_srcport': self.udp_srcport,
            'udp_dstport': self.udp_dstport,
            'eth_src': self.eth_src,
            'eth_dst': self.eth_dst,
            'category': self.category,
            'detected_as': self.detected_as
        } 