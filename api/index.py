from flask import Flask, render_template, redirect, url_for

app = Flask(__name__, template_folder='../templates')

@app.route('/')
def index():
    """
    Redirects the root URL to the calculator page.
    """
    return redirect(url_for('calculator'))

@app.route('/calculator')
def calculator():
    """
    Renders the main calculator page.
    """
    return render_template('calculator.html')