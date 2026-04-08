# api/index.py
from http.server import BaseHTTPRequestHandler
from main import TestFramework # Import your existing class

class handler(BaseHTTPRequestHandler):
    def do_GET(self):
        try:
            # Initialize your framework
            # Note: Ensure config.yaml and workflow.yaml are in the root
            framework = TestFramework("config.yaml", "workflow.yaml")
            framework.execute()
            
            self.send_response(200)
            self.send_header('Content-type', 'text/plain')
            self.end_headers()
            self.wfile.write("Test Framework Executed Successfully".encode())
        except Exception as e:
            self.send_response(500)
            self.end_headers()
            self.wfile.write(f"Error: {str(e)}".encode())
