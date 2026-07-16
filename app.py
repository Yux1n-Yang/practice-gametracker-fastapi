import os
import sqlite3 
import hashlib
from fastapi import FastAPI, Request, Form
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from starlette.middleware.sessions import SessionMiddleware

# ==========================================
# PASSWORD CRYPTOGRAPHY HELPERS
# ==========================================

def hash_password(password: str) -> str:
    """Hashes a plain-text password using PBKDF2 with a unique random salt."""
    salt = os.urandom(16)
    key = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100000)
    return f"{salt.hex()}:{key.hex()}"

def verify_password(stored_password: str, provided_password: str) -> bool:
    """Verifies a password against its stored hash."""
    try:
        salt_hex, key_hex = stored_password.split(":")
        salt = bytes.fromhex(salt_hex)
        key = bytes.fromhex(key_hex)
        new_key = hashlib.pbkdf2_hmac('sha256', provided_password.encode('utf-8'), salt, 100000)
        return key == new_key
    except Exception:
        return False


# ==========================================
# DATABASE INITIALIZATION
# ==========================================

def init_db():
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    
    # 1. Users Table (Uses 'isenable' and 'approved')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY,
            password TEXT,
            isadmin INTEGER DEFAULT 0,
            isenable INTEGER DEFAULT 1,
            approved INTEGER DEFAULT 0
        )
    ''')
    
    # 2. Game Records Table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS game_records (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT,
            game_name TEXT,
            playtime TEXT,
            levels TEXT,
            FOREIGN KEY(username) REFERENCES users(username)
        )
    ''')

    # 3. Games Selection Table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS games (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT UNIQUE
        )
    ''')
    
    # Pre-populate default accounts (Both ryan and xindong are pre-approved = 1)
    cursor.execute("SELECT COUNT(*) FROM users")
    if cursor.fetchone()[0] == 0:
        hashed_ryan = hash_password("12345")
        hashed_xindong = hash_password("00000")
        
        cursor.execute("INSERT INTO users (username, password, isadmin, isenable, approved) VALUES (?, ?, 0, 1, 1)", ("ryan", hashed_ryan))
        cursor.execute("INSERT INTO users (username, password, isadmin, isenable, approved) VALUES (?, ?, 1, 1, 1)", ("xindong", hashed_xindong))
        conn.commit()

    # Pre-populate default games list
    cursor.execute("SELECT COUNT(*) FROM games")
    if cursor.fetchone()[0] == 0:
        default_games = [
            "Minecraft", 
            "Elden Ring", 
            "Valorant", 
            "League of Legends", 
            "Grand Theft Auto V", 
            "Cyberpunk 2077", 
            "Hades"
        ]
        cursor.executemany("INSERT INTO games (name) VALUES (?)", [(g,) for g in default_games])
        conn.commit()

    conn.close()


# Run database setup at startup
init_db()


# ==========================================
# APP INITIALIZATION & MIDDLEWARE
# ==========================================

app = FastAPI()

# Safe: Reads from Render's environment, falls back to a default key locally
SECRET_KEY = os.getenv("SESSION_KEY", "super-secret-random-string")
app.add_middleware(SessionMiddleware, secret_key=SECRET_KEY)

templates = Jinja2Templates(directory="templates")


# ==========================================
# AUTHENTICATION ROUTES
# ==========================================

@app.get("/", response_class=HTMLResponse)
def login_page(request: Request):
    if "user" in request.session:
        return RedirectResponse(url="/dashboard", status_code=302)
    return templates.TemplateResponse(request=request, name="login.html")

@app.post("/login")
def handle_login(request: Request, username: str = Form(...), password: str = Form(...)):
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    cursor.execute("SELECT password, isadmin, isenable, approved FROM users WHERE username = ?", (username,))
    result = cursor.fetchone()
    conn.close()
    
    if result:
        stored_password, is_admin, is_enable, approved = result
        
        # 1. Block login if account is waiting for approval
        if not approved:
            return HTMLResponse(
                content="<h3>Registration Pending</h3>Your account is currently waiting for administrator approval. Please check back later. <br><br><a href='/'>Go back</a>", 
                status_code=403
            )
        
        # 2. Block login if account is suspended
        if not is_enable:
            return HTMLResponse(
                content="<h3>Account Suspended</h3>Your account has been suspended. Please contact an administrator. <br><br><a href='/'>Go back</a>", 
                status_code=403
            )
        
        # 3. Check hashed password securely
        if verify_password(stored_password, password):
            request.session["user"] = username
            request.session["isadmin"] = bool(is_admin)
            return RedirectResponse(url="/dashboard", status_code=303) 
            
    return HTMLResponse(
        content="Invalid username or password. <a href='/'>Go back</a>", 
        status_code=401
    )

@app.get("/logout")
def logout(request: Request):
    request.session.clear()
    return RedirectResponse(url="/", status_code=302)

@app.get("/register", response_class=HTMLResponse)
def register_page(request: Request):
    return templates.TemplateResponse(request=request, name="register.html")

@app.post("/register")
def handle_register(username: str = Form(...), password: str = Form(...)):
    try:
        conn = sqlite3.connect("users.db")
        cursor = conn.cursor()
        hashed_pw = hash_password(password)
        
        # New users default to approved = 0 and isenable = 0
        cursor.execute("INSERT INTO users (username, password, isadmin, isenable, approved) VALUES (?, ?, 0, 0, 0)", (username, hashed_pw))
        conn.commit()
        conn.close()
        return HTMLResponse(
            content="<h3>Registration Request Submitted!</h3>Your profile has been saved. An administrator must approve your account before you can log in. <br><br><a href='/'>Click here to return to login</a>", 
            status_code=201
        )
    except sqlite3.IntegrityError:
        return HTMLResponse(
            content="That username is already taken. <a href='/register'>Try a different one</a>", 
            status_code=400
        )


# ==========================================
# USER DASHBOARD ROUTE
# ==========================================

@app.get("/dashboard", response_class=HTMLResponse)
def dashboard(request: Request):
    user = request.session.get("user")
    isadmin = request.session.get("isadmin", False)
    
    if not user:
        return RedirectResponse(url="/", status_code=302)
        
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    
    # Get user's game records
    cursor.execute("SELECT id, game_name, playtime, levels FROM game_records WHERE username = ?", (user,))
    records = [{"id": row[0], "game_name": row[1], "playtime": row[2], "levels": row[3]} for row in cursor.fetchall()]
    
    # Get all games
    cursor.execute("SELECT name FROM games ORDER BY name ASC")
    games = [row[0] for row in cursor.fetchall()]
    
    conn.close()
    
    return templates.TemplateResponse(
        request=request, 
        name="dashboard.html", 
        context={
            "user": user, 
            "isadmin": isadmin, 
            "records": records, 
            "games": games
        }
    )


# ==========================================
# ADMIN ROUTES (User Management)
# ==========================================

@app.get("/admin/users", response_class=HTMLResponse)
def admin_users_page(request: Request):
    user = request.session.get("user")
    isadmin = request.session.get("isadmin", False)
    
    if not user or not isadmin:
        return RedirectResponse(url="/dashboard", status_code=302)
        
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    cursor.execute("SELECT username, isadmin, isenable, approved FROM users")
    all_users = [
        {
            "username": row[0], 
            "isadmin": bool(row[1]), 
            "isenable": bool(row[2]), 
            "approved": bool(row[3])
        } 
        for row in cursor.fetchall()
    ]
    conn.close()
    
    return templates.TemplateResponse(
        request=request, 
        name="admin_users.html", 
        context={"user": user, "users": all_users}
    )

@app.post("/admin/approve/{target_username}")
def approve_user(request: Request, target_username: str):
    user = request.session.get("user")
    isadmin = request.session.get("isadmin", False)
    
    if not user or not isadmin:
        return RedirectResponse(url="/dashboard", status_code=302)
        
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    cursor.execute("UPDATE users SET approved = 1, isenable = 1 WHERE username = ?", (target_username,))
    conn.commit()
    conn.close()
    return RedirectResponse(url="/admin/users", status_code=303)

@app.post("/admin/toggle/{target_username}")
def toggle_user(request: Request, target_username: str, current_status: int = Form(...)):
    user = request.session.get("user")
    isadmin = request.session.get("isadmin", False)
    
    if not user or not isadmin:
        return RedirectResponse(url="/dashboard", status_code=302)
        
    if user == target_username:
        return HTMLResponse("You cannot disable your own admin account! <a href='/admin/users'>Go back</a>", status_code=400)
        
    new_status = 0 if current_status == 1 else 1
    
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    cursor.execute("UPDATE users SET isenable = ? WHERE username = ?", (new_status, target_username))
    conn.commit()
    conn.close()
    return RedirectResponse(url="/admin/users", status_code=303)

@app.post("/admin/toggle-role/{target_username}")
def toggle_admin_role(request: Request, target_username: str, current_role: int = Form(...)):
    user = request.session.get("user")
    isadmin = request.session.get("isadmin", False)
    
    if not user or not isadmin:
        return RedirectResponse(url="/dashboard", status_code=302)
        
    if user == target_username:
        return HTMLResponse("You cannot demote yourself from Admin status! <a href='/admin/users'>Go back</a>", status_code=400)
        
    new_role = 0 if current_role == 1 else 1
    
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    cursor.execute("UPDATE users SET isadmin = ? WHERE username = ?", (new_role, target_username))
    conn.commit()
    conn.close()
    return RedirectResponse(url="/admin/users", status_code=303)


# ==========================================
# GAME RECORDS CRUD
# ==========================================

@app.post("/game/add")
def add_record(request: Request, game_name: str = Form(...), playtime: str = Form(...), levels: str = Form(...)):
    user = request.session.get("user")
    if not user:
        return RedirectResponse(url="/", status_code=302)
        
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    cursor.execute("INSERT INTO game_records (username, game_name, playtime, levels) VALUES (?, ?, ?, ?)", (user, game_name, playtime, levels))
    conn.commit()
    conn.close()
    return RedirectResponse(url="/dashboard", status_code=303)

@app.get("/game/edit/{record_id}", response_class=HTMLResponse)
def edit_record_page(request: Request, record_id: int):
    user = request.session.get("user")
    if not user:
        return RedirectResponse(url="/", status_code=302)
        
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    cursor.execute("SELECT id, game_name, playtime, levels FROM game_records WHERE id = ? AND username = ?", (record_id, user))
    row = cursor.fetchone()
    
    if not row:
        conn.close()
        return HTMLResponse("Record not found or unauthorized.", status_code=404)
        
    record = {"id": row[0], "game_name": row[1], "playtime": row[2], "levels": row[3]}
    
    cursor.execute("SELECT name FROM games ORDER BY name ASC")
    games = [r[0] for r in cursor.fetchall()]
    conn.close()
    
    return templates.TemplateResponse(
        request=request, 
        name="edit_record.html", 
        context={
            "user": user, 
            "record": record, 
            "games": games
        }
    )

@app.post("/game/edit/{record_id}")
def handle_edit_record(
    request: Request, 
    record_id: int, 
    game_name: str = Form(...), 
    playtime: str = Form(...), 
    levels: str = Form(...)
):
    user = request.session.get("user")
    if not user:
        return RedirectResponse(url="/", status_code=302)
        
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    cursor.execute('''
        UPDATE game_records 
        SET game_name = ?, playtime = ?, levels = ? 
        WHERE id = ? AND username = ?
    ''', (game_name, playtime, levels, record_id, user))
    conn.commit()
    conn.close()
    return RedirectResponse(url="/dashboard", status_code=303)

@app.post("/game/delete/{record_id}")
def delete_record(request: Request, record_id: int):
    user = request.session.get("user")
    if not user:
        return RedirectResponse(url="/", status_code=302)
        
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    cursor.execute("DELETE FROM game_records WHERE id = ? AND username = ?", (record_id, user))
    conn.commit()
    conn.close()
    return RedirectResponse(url="/dashboard", status_code=303)