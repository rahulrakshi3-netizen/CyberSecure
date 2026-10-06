import sys
sys.path.insert(0, '.')
from app import app as application

# Vercel WSGI adapter expects 'app'
app = application
