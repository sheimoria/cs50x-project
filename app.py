import os

from cs50 import SQL
from flask import Flask, flash, jsonify, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.exceptions import default_exceptions, HTTPException, InternalServerError
from werkzeug.security import check_password_hash, generate_password_hash
from helpers import login_required, sgd, error

# Configure application
app = Flask(__name__)

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True

# Ensure responses aren't cached
@app.after_request
def after_request(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response

# Custom filter
app.jinja_env.filters["sgd"] = sgd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_FILE_DIR"] = mkdtemp()
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///ledgio.db")

# Register
@app.route("/register", methods=["GET", "POST"])
def register():

    if request.method == "GET":
        return render_template("register.html")

    else:
        username = request.form.get("username")
        password = request.form.get("password")
        confirmation = request.form.get("confirmation")

        if not username:
            return flash("Please provide a username.", "alert alert-danger")

        usernames = db.execute("SELECT username FROM users;")

        if username in usernames:
            return flash("Sorry, this username is taken. Please choose another one.", "alert alert-danger")

        elif not password:
            return flash("Please provide a password.", "alert alert-danger")

        elif password != confirmation:
            return flash("Sorry, this username is taken. Please choose another one.", "alert alert-danger")

        else:
            db.execute("INSERT INTO users (username, hash) VALUES (?, ?)", username, generate_password_hash(password))
            flash("Registered successfully. Please try logging in.")
            return redirect("/login")

#Log in
@app.route("/login", methods=["GET", "POST"])
def login():

    # Forget any user_id
    session.clear()

    if request.method == "GET":
        return render_template("login.html")

    # User reached route via POST (as by submitting a form via POST)
    else:
        # Ensure username was submitted
        if not request.form.get("username"):
            flash("Please enter a username.", "alert alert-danger")
            return redirect("/login")

        # Ensure password was submitted
        elif not request.form.get("password"):
            flash("Please enter a password.", "alert alert-danger")
            return redirect("/login")

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = ?", request.form.get("username"))

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            flash("Invalid username and/or password.", "alert alert-danger")
            return redirect("/login")

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        return redirect("/")

# Index
@app.route("/")
@login_required
def index():

        # Add transaction
        tags = ["Food", "Transport", "Shopping", "Bills", "Income"]

        # Recent transactions
        transactions = db.execute("SELECT * FROM transactions WHERE user_id = ? ORDER BY date DESC LIMIT 5;", session["user_id"])

        # Monthly report
        summaries = db.execute("SELECT tag, SUM(amount) as total_amount FROM transactions WHERE user_id = ? AND date >= date('now','start of month','-1 month') AND date < date('now','start of month') GROUP BY tag;", session["user_id"])
        balance = 0

        for summary in summaries:
            if summary["tag"] == "Income":
                balance += summary["total_amount"]
            else:
                balance -= summary["total_amount"]

        return render_template("index.html", tags=tags, transactions=transactions, summaries=summaries, balance=balance)

@app.route("/add", methods=["POST"])
@login_required
def add():
        description = request.form.get("description")
        tag = request.form.get("tag")
        date = request.form.get("date")

        if not description or not tag or not date:
            return flash("Please input all fields.", "alert alert-danger")

        try:
            amount = float(request.form.get("amount"))
        except:
            return flash("Invalid amount.", "alert alert-danger")

        if len(date) != 10 or not (date[:4].isdigit() and date[4] == "-" and date[5:7].isdigit() and date[7] == "-" and date[8:].isdigit()):
            return flash("Please input a valid date format.", "alert alert-danger")

        db.execute("INSERT INTO transactions (user_id, description, amount, tag, date) VALUES (?, ?, ?, ?, ?);", session["user_id"], description, amount, tag, date)

        flash("Transaction added successfully.", "alert alert-success")

        return redirect("/")

@app.route("/history", methods=["GET", "POST"])
@login_required
def history():
    if request.method == "GET":
        transactions = db.execute("SELECT * FROM transactions WHERE user_id = ? ORDER BY date DESC;", session["user_id"])
        return render_template("history.html", transactions=transactions)
    else:
        db.execute("DELETE FROM transactions WHERE tid = ?;", request.form.get("delete"))
        flash("Transaction deleted successfully.", "alert alert-success")
        return redirect("/history")

@app.route("/settings", methods=["GET", "POST"])
@login_required
def settings():
    if request.method == "GET":
        return render_template("settings.html")

    else:
        old_hash = db.execute("SELECT hash FROM users WHERE id = ?;", session["user_id"])[0]["hash"]

        if generate_password_hash(request.form.get("old_password")) != old_hash:
            flash("Invalid old password.", "alert alert-danger")
            return redirect("/settings")

        db.execute("UPDATE users SET hash = ?;", generate_password_hash(request.form.get("new_password")))

@app.route("/logout")
def logout():

    # Forget any user_id
    session.clear()

    # Redirect user to signin form
    return redirect("/login")

def errorhandler(e):
    if not isinstance(e, HTTPException):
        e = InternalServerError()
    return error(e.name, e.code)

# Listen for errors
for code in default_exceptions:
    app.errorhandler(code)(errorhandler)