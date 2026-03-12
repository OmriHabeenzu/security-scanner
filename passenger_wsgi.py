import sys
import os

# Add project root to Python path
INTERP = os.path.expanduser('/home/omrihabeenzu/virtualenv/security_scanner/3.11/bin/python3')
if sys.executable != INTERP:
    os.execl(INTERP, INTERP, *sys.argv)

# Add project directory to path
sys.path.insert(0, os.path.dirname(__file__))

# Load environment variables from .env
from dotenv import load_dotenv
load_dotenv(os.path.join(os.path.dirname(__file__), '.env'))

# Create the Flask app
from app import create_app
application = create_app('production')
