# IoT-Framework-Security

A Flask application for monitoring and analyzing network traffic with JWT authentication.

## Project Structure

```
.
├── app/                    # Flask application
│   ├── __init__.py        # Application factory
│   ├── models.py          # Database models
│   └── routes/            # API routes
├── modelData/             # Network traffic data
│   └── data.csv          # Sample network traffic data
├── config.py              # Application configuration
├── manage_db.py           # Database management script
├── periodic_update.py     # Network traffic update script
├── requirements.txt       # Python dependencies
└── run.py                # Application entry point
```

## Setup

1. Create a virtual environment:
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

3. Initialize the database:
```bash
python manage_db.py init
```

## Usage

1. Start the Flask application:
```bash
python run.py
```

2. Run the network traffic update script:
```bash
python periodic_update.py
```

3. Database management:
```bash
# Initialize database
python manage_db.py init

# Reset database
python manage_db.py reset
```

## API Endpoints

- POST /api/login - User authentication
- GET /api/network-traffic - Get network traffic data (requires authentication)

## Default User

- Email: eric@mail.com
- Password: 123