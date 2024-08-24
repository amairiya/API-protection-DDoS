from flask import Flask, request, jsonify
import logging

app = Flask(__name__)

# Configure logging
logging.basicConfig(
    filename='suspicious_activity.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

logger = logging.getLogger()

# Liste de chaînes suspectes
SUSPECT_PATTERNS = [
    "SELECT * FROM", "UNION SELECT", "DROP TABLE", "INSERT INTO",
    "UPDATE SET", "OR 1=1", "';--", "admin' --",
    "<script>", "</script>", "javascript:", "eval(", "document.cookie",
    "onload=", "alert(", "location.href=",
    "; ls", "| whoami", "&& echo", "$(uname -a)", "| cat /etc/passwd",
    "../", "..\\", "%2e%2e%2f", "%2e%2e%5c", "../../etc/passwd", "..%2f..%2f",
    "<!DOCTYPE", "ENTITY xxe SYSTEM", "file://", "!ENTITY % file SYSTEM",
    "php://input", "file://", "http://", "../", "/etc/passwd", "../config.php",
    "system(", "exec(", "shell_exec(", "passthru(", "phpinfo()",
    "username=admin&password=", "user=admin", "password=", "login=", "auth_token=", "id=1 UNION SELECT",
    "Host:", "X-Forwarded-For:", "Referer:", "Content-Length:", "Transfer-Encoding: chunked",
    "GET /?", "POST /"
]


# if "DROP TABLE" in req.args.get('query', ''):

def is_suspicious_request(req):
    # query_string = req.args.get('query', '')    
    # if any(pattern in query_string for pattern in SUSPECT_PATTERNS):
    #     logger.info(f"Suspicious pattern detected: {pattern} in query: {query_string}")
    #     return True
    # return False


    query_string = req.args.get('query', '')  
    for pattern in SUSPECT_PATTERNS:
        if pattern in query_string:
            logger.info(f"Suspicious pattern detected: {pattern} in query: {query_string}")
            return True
    return False



@app.before_request
def check_request():
    if is_suspicious_request(request):
        return jsonify({"error": "Suspicious request detected"}), 400

@app.route('/')
def index():
    return jsonify({"message": "Hello, World!"})

if __name__ == "__main__":
    app.run(debug=True)
