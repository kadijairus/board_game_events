from flask import Flask, render_template, request, jsonify, redirect
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
import bcrypt
import sqlite3
from sqlite3 import Error
import os
import time
import psutil

app = Flask(__name__)
app.secret_key = os.urandom(32)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

DATABASE = 'data.db'


class User(UserMixin):
    def __init__(self, id, username, email, is_admin=False):
        self.id = id
        self.username = username
        self.email = email
        self.is_admin = is_admin


@login_manager.user_loader
def user_loader(user_id):
    cur.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    user = cur.fetchone()
    if user:
        return User(user['id'], user['username'], user['email'], user['is_admin'])
    return None


def init_db():
    # Check if the connection is not None
    conn = sqlite3.connect(DATABASE, check_same_thread=False)
    cur = conn.cursor()
    if conn is not None:
        try:
            # Read the SQL commands from schema.sql
            with open('schema.sql', 'r') as f:
                sql_commands = f.read()

            # Execute the SQL commands to create tables
            conn.executescript(sql_commands)
            conn.commit()

        except Exception as e:
            print(f"Error while executing SQL commands: {str(e)}")
        return cur, conn
    else:
        print("Error! Cannot create the database connection.")
        exit()


def create_event(creator_id, address, place, lng, lat, games, date, time, participants, comments, link):
    cur.execute(
        '''INSERT INTO events (creator_id, address, place, lng, lat, games, date, time, participants, comments, link) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
        (creator_id, address, place, lng, lat, games, date, time, participants, comments, link))
    conn.commit()

@app.route('/new_event', methods=['POST'])
def submit():
    games = request.form.get('lauamangude-nimed')
    date = request.form.get('kuupaev-kellaaeg').split("T")[0]
    time = request.form.get('kuupaev-kellaaeg').split("T")[1]
    address = request.form.get('aadress')
    comments = request.form.get('kommentaarid')
    participants = request.form.get('Osaliste-piirarv')
    link = request.form.get('facebook')
    place = request.form.get('asukoht')

    # Insert data into the database
    create_event(1, address, place, 10, 10, games, date, time, participants, comments, link)

    return redirect("/")

def create_user(username, email, password, is_admin=False):
    password = password.encode('utf-8')
    hashed = bcrypt.hashpw(password, bcrypt.gensalt()).decode('utf-8')

    try:
        cur.execute("INSERT INTO users (username, email, password_hash, is_admin) VALUES (?, ?, ?, ?)",
                    (username, email, hashed, is_admin))
        conn.commit()
        return True
    except sqlite3.IntegrityError as e:
        return False


# Ei tea kas on vajalik funktsioon?
def create_table(conn, create_table_sql):
    """ Create a table from the create_table_sql statement."""
    try:
        c = conn.cursor()
        c.execute(create_table_sql)
    except Error as e:
        print(e)


# See endpoint ei tohiks olla avalikult kättesaadav
@app.route('/users', methods=['GET'])
def get_users():
    cur.execute("SELECT * FROM users")
    rows = cur.fetchall()
    rows = [tuple(row) for row in rows]

    return rows


@app.route('/events', methods=['GET'])
def get_events():
    cur.execute("SELECT * FROM events")
    rows = cur.fetchall()
    rows = [tuple(row) for row in rows]

    # Use jsonify directly and extract the JSON data
    table_json_response = jsonify(rows)
    return table_json_response.get_json()


@app.route('/events_reg/<user_id>', methods=['GET'])
def get_events_reg(user_id):
    cur.execute("""
        SELECT *
        FROM events_reg
        LEFT JOIN events ON events_reg.event_id = events.id
        WHERE events_reg.user_id = ?
        ORDER BY date, time
    """, (user_id,))
    rows = cur.fetchall()
    rows = [tuple(row) for row in rows]
    # Use jsonify directly and extract the JSON data
    reg_events_json_response = jsonify(rows)
    # return reg_events_json_response.get_json()
    # Testimise ajaks json_response. Töötab kui id täita url-is kujul /events_reg/1
    return reg_events_json_response


@app.route('/submit', methods=['POST'])
def submit_form():
    data = request.json
    creator_id = data['creator_id']
    address = data['address']
    place = data['place']
    lng = ['24.75309420']
    lat = ['59.43705315']
    games = data['games']
    date = data['date']
    time = data['time']
    participants = data['participants']
    comments = data['comments']
    link = data['link']

    cur.execute(
        '''INSERT INTO events (creator_id, address, place, lng, lat, games, date, time, participants, comments, link) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
        (creator_id, address, place, lng, lat, games, date, time, participants, comments, link))
    conn.commit()
    return jsonify({"message": "Form data submitted successfully"})


'''
HTML faile võtab /template kaustast
'''


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/otsi")
def otsi():
    table_json = get_events()
    # Pass the table_json to render_template
    return render_template("otsi.html", table_json=table_json)


@app.route("/kaart")
def kaart():
    return render_template("kaart.html")


@app.route("/kaart_suur")
def kaart_suur():
    return render_template("kaart_suur.html")


@app.route("/loo")
def loo():
    return render_template("loo.html")


@app.route("/tutvustus")
def tutvustus():
    return render_template("tutvustus.html")


@app.route("/kohad")
def kohad():
    return render_template("kohad.html")


@app.route("/profiil", methods=['GET', 'POST'])
def profiil():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password').encode('utf-8')

        cur.execute("SELECT * FROM users WHERE email = ?", (email,))
        user = cur.fetchone()

        if user:
            stored_password_hash = user['password_hash']
            if isinstance(stored_password_hash, str):
                stored_password_hash = stored_password_hash.encode('utf-8')

            if bcrypt.checkpw(password, stored_password_hash):
                user = User(user['id'], user['username'], user['email'], user['is_admin'])
                login_user(user)
                return jsonify({"status": "success", "message": "You are logged in as: " + current_user.username}), 409
                #return render_template("profiil.html")
            else:
                #return jsonify({"status": "error", "message": "Invalid email or password."}), 401
                return render_template("login.html")
        else:
            #return jsonify({"status": "error", "message": "User not found."}), 404
            return render_template("login.html")

        # return render_template("index.html")

    if request.method == 'GET':
        if current_user.is_authenticated:
            #return render_template("profiil.html")
            return jsonify({"status": "successful", "message": "You are logged in as: " + current_user.username}), 409
        return render_template("login.html")


@app.route('/register', methods=['GET', 'POST'])
def register_account():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        password_confirm = request.form.get('password_confirm')

        # TODO: Check for password minimum requirements

        if password_confirm != password:
            return jsonify({"status": "error", "message": "Password and confirm password are not the same"}), 409

        if create_user(username, email, password):
            #return jsonify({"status": "success", "message": "Account registered."}), 201
            return redirect("/profiil", code=302)
        else:
            return jsonify({"status": "error", "message": "Username or email already exists."}), 409
    if request.method == 'GET':
        return render_template("register.html")

@app.route('/logout')
def logout():
    logout_user()
    return redirect('/')

'''
Admin kohad
'''

@app.route("/admin", methods=['GET', 'POST'])
def admin():
    if not current_user.is_authenticated or not current_user.is_admin:
        if request.method == 'GET':
            return render_template("admin_login.html")
        if request.method == 'POST':
            username = request.form.get('username')
            password = request.form.get('password').encode('utf-8')
            cur.execute("SELECT * FROM users WHERE username = ?", (username,))
            user = cur.fetchone()

            if user:
                stored_password_hash = user['password_hash']
                if isinstance(stored_password_hash, str):
                    stored_password_hash = stored_password_hash.encode('utf-8')

                if not user["is_admin"]:
                    # return jsonify({"status": "error", "message": "Invalid email or password."}), 401
                    return render_template("admin_login.html")

                if bcrypt.checkpw(password, stored_password_hash):
                    user = User(user['id'], user['username'], user['email'], user['is_admin'])
                    login_user(user)
                    # return jsonify({"status": "success", "message": "Login successful."}), 200
                    return render_template("admin.html")
                else:
                    # return jsonify({"status": "error", "message": "Invalid email or password."}), 401
                    return render_template("admin_login.html")
            else:
                # return jsonify({"status": "error", "message": "User not found."}), 404
                return render_template("admin_login.html")


    return render_template("admin.html")


@app.route("/admin/usage")
def cpu():
    cpu_usage = psutil.cpu_percent(interval=1)
    memory_usage = psutil.virtual_memory().percent
    try:
        net_stat = psutil.net_io_counters(pernic=True, nowrap=True)["Ethernet"]
        net_in_1 = net_stat.bytes_recv
        net_out_1 = net_stat.bytes_sent
        time.sleep(1)
        net_stat = psutil.net_io_counters(pernic=True, nowrap=True)["Ethernet"]
        net_in_2 = net_stat.bytes_recv
        net_out_2 = net_stat.bytes_sent

        net_in = round((net_in_2 - net_in_1) / 1024 / 1024, 3)
        net_out = round((net_out_2 - net_out_1) / 1024 / 1024, 3)
    except KeyError:
        net_in = 0
        net_out = 0

    return jsonify({"cpu_usage": str(cpu_usage), "memory_usage": str(memory_usage), "net_in": str(net_in),
                    "net_out": str(net_out)})


@app.route("/admin/kasutajad")
def admin_kasutajad():
    table_json = get_users()
    print(table_json)
    return render_template("admin_kasutajad.html", table_json=table_json)

@app.route("/admin/uritused")
def admin_uritused():
    table_json = get_events()
    print(table_json)
    return render_template("admin_uritused.html", table_json=table_json)


if __name__ == "__main__":
    # debug eemaldada kui valmis
    # Kui andmebaasi ei eksisteeri siis loo see ja lisa algsed andmed
    if not os.path.exists("data.db"):
        cur, conn = init_db()
        conn.row_factory = sqlite3.Row
        create_event(1, "Tänav", "Tallinn", 24.75309420, 59.43705315, "Male", "2023-12-12", "12:00", 10,
                     "Kommentaar", "https://www.google.com")
        create_user("test", "test@test.test", "test")
        create_user("admin", "admin@test.test", "admin", is_admin=True)
    else:
        conn = sqlite3.connect(DATABASE, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()

    app.run(host='0.0.0.0', port=80, debug=True)
