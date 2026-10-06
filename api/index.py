from app import app as application

# Vercel requires handler named 'app' in some cases; also can use asgi? better to set both
app = application

