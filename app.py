from flask import Flask, render_template, request, jsonify
from main import password_strength_checker, osint_toolkit_integration

app = Flask(__name__)

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/check_password', methods=['POST'])
def check_password():
    password = request.form['password']
    result = password_strength_checker(password)
    return jsonify(result=result)

@app.route('/osint_search', methods=['POST'])
def osint_search():
    query = request.form['query']
    result = osint_toolkit_integration(query)
    return jsonify(result=result)

if __name__ == '__main__':
    app.run(debug=True) 