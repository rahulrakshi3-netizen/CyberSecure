from app import app as application

def handler(environ, start_response):
    return application(environ, start_response)

