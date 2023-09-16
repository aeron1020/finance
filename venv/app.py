import os
from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required, lookup, usd

# Configure application
app = Flask(__name__)

# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")

# Make sure API key is set
if not os.environ.get("API_KEY"):
    raise RuntimeError("API_KEY not set")


@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


@app.route("/", methods=["GET", "POST"])
@login_required
def index():
    """Show portfolio of stocks"""
    if request.method == 'POST':
        quantity = request.form.get("quantity")
        action = request.form.get("action")

        if not quantity:
            return apology("give a quantity to buy/sell")

        if action == 'buy':

            symbol = request.form.get("stock_symbol").upper()
            quantity = int(quantity)
            api_lookup_symbol = lookup(symbol)
            look_up_name = api_lookup_symbol["name"]
            look_up_price = api_lookup_symbol["price"]
            look_up_symbol = api_lookup_symbol["symbol"]
            purchase_total = (quantity * look_up_price)

            cash = db.execute(
                "SELECT cash FROM users WHERE id = ?", session["user_id"])

            if cash[0]["cash"] - purchase_total >= 0:
                # PURCHASES TABLE
                remaining_cash = (cash[0]["cash"] - purchase_total)
                db.execute(
                    "INSERT INTO purchases (item_symbol, item_name, shares_quantity, price, purchase_total, remaining_cash) VALUES (?, ?, ?, ?, ?, ?)", look_up_symbol, look_up_name, quantity, usd(look_up_price), purchase_total, usd(remaining_cash))
                # USERS cash
                db.execute(
                    "UPDATE users SET cash = ? WHERE id = ?", remaining_cash, session["user_id"])

                # HISTORY LOG
                db.execute(
                    "INSERT INTO history (item_symbol, shares_quantity, price) VALUES (?, ?, ?)", symbol, quantity, usd(look_up_price))

                # MYSTOCKS TABLE
                if len(db.execute("SELECT * FROM mystocks WHERE stock_symbol = ?", symbol)) == 1:

                    number_of_shares = db.execute(
                        "SELECT number_of_shares FROM mystocks WHERE stock_symbol = ?", symbol)
                    number_of_shares = float(
                        number_of_shares[0]['number_of_shares'] + quantity)

                    stock_value = db.execute(
                        "SELECT stock_value FROM mystocks WHERE stock_symbol = ?", symbol)
                    stock_value = stock_value[0]["stock_value"]
                    stock_value = float(stock_value)
                    stock_values = (stock_value + purchase_total)
                    price_update = (stock_values / number_of_shares)

                    db.execute(
                        "UPDATE mystocks SET number_of_shares = ?, price_update = ?,  stock_value = ? WHERE stock_symbol = ? AND id = ?", number_of_shares, usd(price_update), stock_values, symbol, db.execute("SELECT id FROM mystocks WHERE stock_symbol = ?", symbol)[0]["id"])

                else:
                    db.execute("INSERT INTO mystocks (stock_name, stock_symbol, number_of_shares, price_update, stock_value) VALUES (?,?,?,?,?) ",
                               look_up_name, look_up_symbol, quantity, usd(look_up_price), purchase_total)

                flash("Successful Transaction")

                return redirect("/")

            return apology("Insuficient cash")

        elif action == 'sell':
            symbol = request.form.get("stock_symbol").upper()
            quantity = int(quantity)

            current_stock_value = db.execute(
                "SELECT stock_value FROM mystocks WHERE stock_symbol = ? AND id = ?", symbol, db.execute("SELECT id FROM mystocks WHERE stock_symbol = ?", symbol)[0]["id"])
            current_number_of_shares = db.execute(
                "SELECT number_of_shares FROM mystocks WHERE stock_symbol = ? AND id = ?", symbol, db.execute("SELECT id FROM mystocks WHERE stock_symbol = ?", symbol)[0]["id"])
            if (current_number_of_shares[0]['number_of_shares']) >= quantity:

                api_lookup_symbol = lookup(symbol)
                look_up_name = api_lookup_symbol["name"]
                look_up_price = api_lookup_symbol["price"]
                look_up_symbol = api_lookup_symbol["symbol"]
                sales_total = (quantity * look_up_price)
                cash = db.execute(
                    "SELECT cash FROM users WHERE id = ?", session["user_id"])

                new_number_of_shares = (
                    float(current_number_of_shares[0]['number_of_shares']) - quantity)
                new_stock_value = (
                    float(current_stock_value[0]['stock_value']) - sales_total)

                remaining_cash = (cash[0]["cash"] + sales_total)

                if new_number_of_shares != 0:
                    price_value = (new_stock_value / new_number_of_shares)
                else:
                    price_value = new_stock_value

                # UPDATE MYSALES
                db.execute("INSERT INTO mysales (item_symbol, item_name, shares_quantity, price, sales_total, remaining_cash) VALUES (?, ?, ?, ?, ?, ?)",
                           look_up_symbol, look_up_name, quantity, usd(look_up_price), sales_total, usd(remaining_cash))

                db.execute("UPDATE users SET cash = ? WHERE id = ?",
                           remaining_cash, session["user_id"])

                # UPDATE MYSTOCKS
                db.execute("UPDATE mystocks SET number_of_shares = ?, price_update = ?, stock_value = ? WHERE stock_symbol = ? AND id = ?", new_number_of_shares, usd(
                    price_value), new_stock_value, symbol, db.execute("SELECT id FROM mystocks WHERE stock_symbol = ?", symbol)[0]["id"])

                # HISTORY LOG
                # Negative prefix
                neg_prefix = "-"
                quantity = neg_prefix + str(quantity)

                db.execute(
                    "INSERT INTO history (item_symbol, shares_quantity, price) VALUES (?, ?, ?)", look_up_symbol, quantity, usd(look_up_price))

                flash("Successful Transaction")
                return redirect("/")

            return apology("Insuficient stock")

    shares = db.execute(
        "SELECT stock_name, stock_symbol, number_of_shares, price_update, stock_value FROM mystocks WHERE number_of_shares > ? GROUP BY stock_name", 0)

    remaining_cash = db.execute(
        "SELECT cash FROM users WHERE id = ?", session["user_id"])

    cash = float(remaining_cash[0]['cash'])

    # Get the stock value to add with cash
    stocks = db.execute(
        "SELECT SUM(CAST((stock_value) AS FLOAT)) FROM mystocks")

    # Get only the value
    if stocks is None:
        stocks = 0
    else:
        stocks = stocks[0]['SUM(CAST((stock_value) AS FLOAT))']

    # Total the cash and stock to reflect in index.html
    if stocks is not None:
        assets = (cash + stocks)
    else:
        assets = (cash)

    return render_template("index.html", purchases=shares, total_cash=cash, assets=assets)


@ app.route("/buy", methods=["GET", "POST"])
@ login_required
def buy():
    """Buy shares of stock"""
    if request.method == "POST":
        if not lookup(request.form.get("symbol").upper()):
            return apology("must provide symbol")

        if not request.form.get("shares").isdigit():
            return apology("must provide number of shares")

        elif int(request.form.get("shares")) <= 0:
            return apology("must provide positive number")

        else:
            cap_symbol = request.form.get("symbol").upper()
            api_lookup = lookup(request.form.get("symbol"))
            shares_quantity = int(request.form.get("shares"))
            look_up_name = api_lookup["name"]
            look_up_price = api_lookup["price"]
            look_up_symbol = api_lookup["symbol"]
            purchase_total = (shares_quantity * look_up_price)
            cash = db.execute(
                "SELECT cash FROM users WHERE id = ?", session["user_id"])

            if cash[0]["cash"] - purchase_total >= 0:

                # PURCHASES TABLE
                remaining_cash = (cash[0]["cash"] - purchase_total)
                db.execute(
                    "INSERT INTO purchases (item_symbol, item_name, shares_quantity, price, purchase_total, remaining_cash) VALUES (?, ?, ?, ?, ?, ?)", look_up_symbol, look_up_name, shares_quantity, usd(look_up_price), purchase_total, usd(remaining_cash))
                # Update users cash
                db.execute(
                    "UPDATE users SET cash = ? WHERE id = ?", remaining_cash, session["user_id"])

                # HISTORY LOG
                db.execute(
                    "INSERT INTO history (item_symbol, shares_quantity, price) VALUES (?, ?, ?)", look_up_symbol, shares_quantity, usd(look_up_price))

                # MYSTOCKS TABLE
                # Check the symbol in mystocks
                if len(db.execute("SELECT * FROM mystocks WHERE stock_symbol = ?", cap_symbol)) == 1:

                    number_of_shares = db.execute(
                        "SELECT number_of_shares FROM mystocks WHERE stock_symbol = ?", cap_symbol)
                    number_of_shares = float(
                        number_of_shares[0]['number_of_shares'] + shares_quantity)

                    stock_value = db.execute(
                        "SELECT stock_value FROM mystocks WHERE stock_symbol = ?", cap_symbol)
                    stock_value = stock_value[0]["stock_value"]
                    stock_value = float(stock_value)
                    stock_values = (stock_value + purchase_total)
                    price_update = (stock_values / number_of_shares)

                    db.execute(
                        "UPDATE mystocks SET number_of_shares = ?, price_update = ?,  stock_value = ? WHERE stock_symbol = ? AND id = ?", number_of_shares, usd(price_update), stock_values, cap_symbol, db.execute("SELECT id FROM mystocks WHERE stock_symbol = ?", cap_symbol)[0]["id"])
                # Add to stock if first log
                else:
                    db.execute("INSERT INTO mystocks (stock_name, stock_symbol, number_of_shares, price_update, stock_value) VALUES (?,?,?,?,?) ",
                               look_up_name, look_up_symbol, shares_quantity, usd(look_up_price), purchase_total)

                flash("Successful Transaction")

                return redirect("/")
            # Insuficient cash
            return apology("Insuficient cash")

    return render_template("buy.html")


@ app.route("/history")
@ login_required
def history():
    """Show history of transactions"""
    # History
    logs = db.execute("SELECT * FROM history")
    return render_template("history.html", logs=logs)

    # return apology("TODO")


@ app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = ?",
                          request.form.get("username"))

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")


@ app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")


@ app.route("/quote", methods=["GET", "POST"])
@ login_required
def quote():
    """Get stock quote."""
    # If method is POST
    if request.method == "POST":
        # If no input symbol
        if not lookup(request.form.get("symbol")):
            return apology("Input correct a symbol")

        else:
            # Lookup the stock symbol
            symbol = request.form.get("symbol")
            # Calling the lookup function
            symbol_quoted = lookup(symbol)
            # If invalid symbol
            if symbol_quoted == None:
                apology("Invalid symbol")
            # Rendering template to the quoted.html and passing the values via Jinja
            return render_template("quoted.html", name=symbol_quoted["name"], price=usd(symbol_quoted["price"]), symbol=symbol_quoted["symbol"])

    # If method is GET
    return render_template("quote.html")


@ app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    # If method is POST
    if request.method == "POST":
        # If no username input
        if not request.form.get("username"):
            return apology("Please complete the registration form")

        # If no password input
        elif not request.form.get("password"):
            return apology("Please complete the registration form")

        # # Password must be 8 char long
        # elif len(request.form.get("password")) <= 8:
        #     return apology("Password must be 8 char long")

        # If form is completed
        else:
            username = request.form.get("username")
            password = request.form.get("password")
            password_confirmation = request.form.get("confirmation")
            password_hash = generate_password_hash(password)
            # Ensure username exists
            reg_username = db.execute("SELECT * FROM users WHERE username = ?",
                                      request.form.get("username"))
            if password != password_confirmation:
                return apology("Password does not match.")

            elif len(reg_username) == 1:
                return apology("Sorry, this username is already taken.")

            # # Uppercase
            # elif not any(x.isupper() for x in request.form.get("password")):
            #     return apology("Password must contain atleast one uppercase letter")
            # # Lowercase
            # elif not any(x.islower() for x in request.form.get("password")):
            #     return apology("Password must contain atleast one lowercase letter")
            # # Number
            # elif not any(x.isdigit() for x in request.form.get("password")):
            #     return apology("Password must contain atleast one number")

            # If all okay, add it to the database
            else:
                db.execute(
                    "INSERT INTO users (username, hash) VALUES (?, ?)", username, password_hash)

                flash("You are registered!")
                return redirect("/login")

    # If method is GET
    return render_template("register.html")


@ app.route("/sell", methods=["GET", "POST"])
@ login_required
def sell():
    """Sell shares of stock"""
    # If method is POST
    shares = db.execute(
        "SELECT stock_symbol FROM mystocks WHERE number_of_shares > ?", 0)

    if request.method == "POST":
        sell_symbol = request.form.get("symbol").upper()
        sell_share = request.form.get("shares")

        if not sell_symbol:
            return apology("must provide symbol you sell")

        elif not sell_share:
            return apology("must provide number of shares you sell")

        elif int(sell_share) <= 0:
            return apology("must provide positive number")

        else:

            current_stock_value = db.execute(
                "SELECT stock_value FROM mystocks WHERE stock_symbol = ? AND id = ?", sell_symbol, db.execute("SELECT id FROM mystocks WHERE stock_symbol = ?", sell_symbol)[0]["id"])
            current_number_of_shares = db.execute(
                "SELECT number_of_shares FROM mystocks WHERE stock_symbol = ? AND id = ?", sell_symbol, db.execute("SELECT id FROM mystocks WHERE stock_symbol = ?", sell_symbol)[0]["id"])
            if (current_number_of_shares[0]['number_of_shares']) >= int(sell_share):

                api_lookup = lookup(request.form.get("symbol"))
                look_up_name = api_lookup["name"]
                look_up_price = api_lookup["price"]
                look_up_symbol = api_lookup["symbol"]
                shares_quantity = int(request.form.get("shares"))
                sales_total = (shares_quantity * look_up_price)
                cash = db.execute(
                    "SELECT cash FROM users WHERE id = ?", session["user_id"])

                new_number_of_shares = (
                    float(current_number_of_shares[0]['number_of_shares']) - int(sell_share))
                new_stock_value = (
                    float(current_stock_value[0]['stock_value']) - sales_total)

                if new_number_of_shares != 0:
                    price_value = (new_stock_value / new_number_of_shares)
                else:
                    price_value = new_stock_value

                remaining_cash = (cash[0]["cash"] + sales_total)

                # UPDATE MYSALES
                db.execute("INSERT INTO mysales (item_symbol, item_name, shares_quantity, price, sales_total, remaining_cash) VALUES (?, ?, ?, ?, ?, ?)",
                           look_up_symbol, look_up_name, shares_quantity, usd(look_up_price), sales_total, usd(remaining_cash))

                db.execute("UPDATE users SET cash = ? WHERE id = ?",
                           remaining_cash, session["user_id"])

                # UPDATE MYSTOCKS
                db.execute("UPDATE mystocks SET number_of_shares = ?, price_update = ?, stock_value = ? WHERE stock_symbol = ? AND id = ?", new_number_of_shares, usd(
                    price_value), new_stock_value, sell_symbol, db.execute("SELECT id FROM mystocks WHERE stock_symbol = ?", sell_symbol)[0]["id"])

                # HISTORY LOG
                # Negative prefix
                neg_prefix = "-"
                shares_quantity = neg_prefix + str(shares_quantity)

                db.execute(
                    "INSERT INTO history (item_symbol, shares_quantity, price) VALUES (?, ?, ?)", look_up_symbol, shares_quantity, usd(look_up_price))

                flash("Successful Transaction")
                return redirect("/")

            return apology("Insuficient stock")

    return render_template("sell.html", shares=shares)
    # return apology("TODO")


@ app.route("/settings", methods=["GET", "POST"])
@ login_required
def settings():
    """Settings"""

    return render_template("settings.html")


@ app.route("/changepassword", methods=["GET", "POST"])
@ login_required
def changepassword():
    """Change Password"""

    if request.method == "POST":
        old_password = request.form.get("old_password")
        new_password = request.form.get("new_password")
        confirmation = request.form.get("confirmation")

        if not old_password:
            return apology("Provide your old password", 403)

        elif not new_password:
            return apology("Provide your new password", 403)

        elif not confirmation:
            return apology("Retype your new password", 403)

        else:
            if new_password != confirmation:
                return apology("Your new password do not match", 403)

            db_old_pass = db.execute(
                "SELECT hash FROM users WHERE id = ?",  (session['user_id']))[0]['hash']
            if check_password_hash(db_old_pass, old_password):

                db.execute("UPDATE users SET hash ? WHERE id = ?", generate_password_hash(
                    new_password), session['user_id'])

                flash("You've successfully changed your password")
                return redirect("/")
            else:
                flash("Previous password do not match")
                return redirect("/changepassword")

    return render_template("changepassword.html")


@ app.route("/add_funds", methods=["GET", "POST"])
@ login_required
def add_funds():
    """Check current user"""
    password = db.execute(
        "SELECT hash FROM users WHERE id = ?",  (session['user_id']))[0]['hash']
    if request.method == "POST":
        verification = (request.form.get("password"))
        if not verification:
            return apology("Enter your password")

        elif not check_password_hash(password, verification):
            return apology("Incorrect password")

        return redirect("/add_funds_db")

    return render_template("add_funds.html")


@ app.route("/add_funds_db", methods=["GET", "POST"])
@ login_required
def add_funds_db():
    if request.method == "POST":
        funds = request.form.get("funds")

        if not funds:
            return apology("Enter amount")

        elif not funds.isdigit():
            return apology("Enter amount only")

        else:
            funds = float(funds)
            cash = db.execute(
                "SELECT cash FROM users WHERE id = ?", session["user_id"])
            cash = cash[0]["cash"]

            total_funds = cash + funds

            # Update cash
            db.execute("UPDATE users SET cash = ? WHERE id = ?", total_funds, session["user_id"])

            # Update History
            db.execute(
                "INSERT INTO history (item_symbol, shares_quantity, price) VALUES (?, ?, ?)", "Additional Funds", funds, "---")


        flash("Successful Transaction")
        return redirect("/")

    return render_template("add_funds_db.html")


# Allow users to add additional cash to their account.
# Allow users to buy more shares or sell shares of stocks they already own via index itself, without having to type stocks’ symbols manually.
# Implement some other feature of comparable scope.


# delete from purchases;
# delete from mysales;
# delete from mystocks;
# delete from users;
# delete from history;
# update users set cash = 10000 where id = 1;
# DELETE FROM sqlite_sequence WHERE name = 'mysales';
# DELETE FROM sqlite_sequence WHERE name = 'mystocks';
# DELETE FROM sqlite_sequence WHERE name = 'purchases';
# DELETE FROM sqlite_sequence WHERE name = 'users';
