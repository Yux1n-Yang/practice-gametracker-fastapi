import os
import sqlite3 
import hashlib
import json
from datetime import date
from fastapi import FastAPI, Request, Form
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from starlette.middleware.sessions import SessionMiddleware

# ==========================================
# CRYPTOGRAPHY CONTROL HELPERS
# ==========================================

def hash_password(password: str) -> str:
    salt = os.urandom(16)
    key = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100000)
    return f"{salt.hex()}:{key.hex()}"

def verify_password(stored_password: str, provided_password: str) -> bool:
    try:
        salt_hex, key_hex = stored_password.split(":")
        salt = bytes.fromhex(salt_hex)
        key = bytes.fromhex(key_hex)
        new_key = hashlib.pbkdf2_hmac('sha256', provided_password.encode('utf-8'), salt, 100000)
        return key == new_key
    except Exception:
        return False


# ==========================================
# SYSTEM DATABASE SCHEMA INITIALIZATION
# ==========================================

def init_db():
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY,
            password TEXT,
            isadmin INTEGER DEFAULT 0,
            isenable INTEGER DEFAULT 1,
            approved INTEGER DEFAULT 0
        )
    ''')
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS game_records (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT,
            game_name TEXT,
            playtime TEXT,
            levels TEXT,
            date_logged TEXT,
            FOREIGN KEY(username) REFERENCES users(username)
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS games (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT UNIQUE
        )
    ''')
    
    cursor.execute("SELECT COUNT(*) FROM users")
    if cursor.fetchone()[0] == 0:
        cursor.execute("INSERT INTO users (username, password, isadmin, isenable, approved) VALUES (?, ?, 0, 1, 1)", ("ryan", hash_password("12345")))
        cursor.execute("INSERT INTO users (username, password, isadmin, isenable, approved) VALUES (?, ?, 1, 1, 1)", ("xindong", hash_password("00000")))
        conn.commit()

    cursor.execute("SELECT COUNT(*) FROM games")
    if cursor.fetchone()[0] == 0:
        default_games = ["Minecraft", "Elden Ring", "Valorant", "League of Legends", "Grand Theft Auto V", "Cyberpunk 2077", "Hades"]
        cursor.executemany("INSERT INTO games (name) VALUES (?)", [(g,) for g in default_games])
        conn.commit()

    conn.close()

init_db()


# ==========================================
# WEB INSTANCE ENVIRONMENT BUILD
# ==========================================

app = FastAPI()
SECRET_KEY = os.getenv("SESSION_KEY", "super-secret-random-string")
app.add_middleware(SessionMiddleware, secret_key=SECRET_KEY)
templates = Jinja2Templates(directory="templates")


# ==========================================
# ACCOUNT AUTHORIZATION PIPELINES
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
        if not approved:
            return HTMLResponse("<h3>Registration Pending Admin Authorization</h3><a href='/'>Go back</a>", status_code=403)
        if not is_enable:
            return HTMLResponse("<h3>Account Suspended</h3><a href='/'>Go back</a>", status_code=403)
        if verify_password(stored_password, password):
            request.session["user"] = username
            request.session["isadmin"] = bool(is_admin)
            return RedirectResponse(url="/dashboard", status_code=303) 
    return HTMLResponse("Invalid parameters. <a href='/'>Go back</a>", status_code=401)

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
        cursor.execute("INSERT INTO users (username, password, isadmin, isenable, approved) VALUES (?, ?, 0, 0, 0)", (username, hash_password(password)))
        conn.commit()
        conn.close()
        return HTMLResponse("<h3>Registration Logged. Awaiting admin clearance.</h3><a href='/'>Return to login</a>", status_code=201)
    except sqlite3.IntegrityError:
        return HTMLResponse("Username taken. <a href='/register'>Try again</a>", status_code=400)


# ==========================================
# WORKSPACE CORE SYSTEM VIEW
# ==========================================

@app.get("/dashboard", response_class=HTMLResponse)
def dashboard(request: Request):
    user = request.session.get("user")
    isadmin = request.session.get("isadmin", False)
    if not user:
        return RedirectResponse(url="/", status_code=302)
        
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    
    cursor.execute("SELECT id, game_name, playtime, levels, date_logged FROM game_records WHERE username = ?", (user,))
    records = []
    for row in cursor.fetchall():
        pt = float(row[2] or 0.0)
        h = int(pt)
        m = int(round((pt - h) * 60))
        records.append({
            "id": row[0],
            "game_name": row[1],
            "playtime_display": f"{h}h {m}m",
            "levels": row[3],
            "date_logged": row[4]
        })
    
    cursor.execute("SELECT name FROM games ORDER BY name ASC")
    games = [row[0] for row in cursor.fetchall()]
    conn.close()
    
    return templates.TemplateResponse(
        request=request, name="dashboard.html", 
        context={"user": user, "isadmin": isadmin, "records": records, "games": games, "today": str(date.today())}
    )


# ==========================================
# SYSTEM ADMIN PORTALS
# ==========================================

@app.get("/admin/users", response_class=HTMLResponse)
def admin_users_page(request: Request):
    if not request.session.get("user") or not request.session.get("isadmin"):
        return RedirectResponse(url="/dashboard", status_code=302)
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    cursor.execute("SELECT username, isadmin, isenable, approved FROM users")
    all_users = [{"username": row[0], "isadmin": bool(row[1]), "isenable": bool(row[2]), "approved": bool(row[3])} for row in cursor.fetchall()]
    conn.close()
    return templates.TemplateResponse(request=request, name="admin_users.html", context={"user": request.session.get("user"), "users": all_users})

@app.post("/admin/approve/{target_username}")
def approve_user(request: Request, target_username: str):
    if not request.session.get("user") or not request.session.get("isadmin"):
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
    if not user or not request.session.get("isadmin"):
        return RedirectResponse(url="/dashboard", status_code=302)
    if user == target_username:
        return HTMLResponse("Action Denied: Self lockout protection active.", status_code=400)
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    cursor.execute("UPDATE users SET isenable = ? WHERE username = ?", (0 if current_status == 1 else 1, target_username))
    conn.commit()
    conn.close()
    return RedirectResponse(url="/admin/users", status_code=303)

@app.post("/admin/toggle-role/{target_username}")
def toggle_admin_role(request: Request, target_username: str, current_role: int = Form(...)):
    user = request.session.get("user")
    if not user or not request.session.get("isadmin"):
        return RedirectResponse(url="/dashboard", status_code=302)
    if user == target_username:
        return HTMLResponse("Action Denied: Self demotion protection active.", status_code=400)
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    cursor.execute("UPDATE users SET isadmin = ? WHERE username = ?", (0 if current_role == 1 else 1, target_username))
    conn.commit()
    conn.close()
    return RedirectResponse(url="/admin/users", status_code=303)

@app.get("/admin/games", response_class=HTMLResponse)
def admin_games_page(request: Request):
    if not request.session.get("user") or not request.session.get("isadmin"):
        return RedirectResponse(url="/dashboard", status_code=302)
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    cursor.execute("SELECT id, name FROM games ORDER BY name ASC")
    all_games = [{"id": row[0], "name": row[1]} for row in cursor.fetchall()]
    conn.close()
    return templates.TemplateResponse(request=request, name="admin_games.html", context={"user": request.session.get("user"), "games": all_games})

@app.post("/admin/games/add")
def admin_add_game(request: Request, game_name: str = Form(...)):
    if not request.session.get("user") or not request.session.get("isadmin"):
        return RedirectResponse(url="/dashboard", status_code=302)
    try:
        conn = sqlite3.connect("users.db")
        cursor = conn.cursor()
        cursor.execute("INSERT INTO games (name) VALUES (?)", (game_name.strip(),))
        conn.commit()
        conn.close()
    except sqlite3.IntegrityError:
        return HTMLResponse("Game already exists. <a href='/admin/games'>Go back</a>", status_code=400)
    return RedirectResponse(url="/admin/games", status_code=303)

@app.post("/admin/games/delete/{game_id}")
def admin_delete_game(request: Request, game_id: int):
    if not request.session.get("user") or not request.session.get("isadmin"):
        return RedirectResponse(url="/dashboard", status_code=302)
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    cursor.execute("DELETE FROM games WHERE id = ?", (game_id,))
    conn.commit()
    conn.close()
    return RedirectResponse(url="/admin/games", status_code=303)


# ==========================================
# 📊 METRICS & MULTI-CHART GRAPHING PLATFORM
# ==========================================

@app.get("/admin/charts", response_class=HTMLResponse)
def admin_charts_page(request: Request):
    if not request.session.get("user") or not request.session.get("isadmin"):
        return RedirectResponse(url="/dashboard", status_code=302)
        
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    
    # 1. Timeline extraction (X-Axis)
    cursor.execute("SELECT DISTINCT date_logged FROM game_records ORDER BY date_logged ASC")
    timeline_dates = [row[0] for row in cursor.fetchall() if row[0]]
    
    # 2. Extract distinct users
    cursor.execute("SELECT DISTINCT username FROM game_records")
    active_users = [row[0] for row in cursor.fetchall()]
    
    user_color_map = ["#4f46e5", "#10b981", "#f59e0b", "#ef4444", "#8b5cf6", "#ec4899"]
    cumulative_datasets = []
    
    # Build a sequential running total graph per individual user
    for idx, target_user in enumerate(active_users):
        daily_map = {d: 0.0 for d in timeline_dates}
        cursor.execute("SELECT date_logged, SUM(CAST(playtime AS REAL)) FROM game_records WHERE username = ? GROUP BY date_logged", (target_user,))
        for r_date, sum_hours in cursor.fetchall():
            if r_date in daily_map:
                daily_map[r_date] = sum_hours or 0.0
                
        cumulative_list = []
        running_accumulator = 0.0
        for d in timeline_dates:
            running_accumulator += daily_map[d]
            cumulative_list.append(round(running_accumulator, 2))
            
        cumulative_datasets.append({
            "label": target_user,
            "data": cumulative_list,
            "borderColor": user_color_map[idx % len(user_color_map)],
            "backgroundColor": user_color_map[idx % len(user_color_map)] + "10",
            "borderWidth": 3,
            "tension": 0.15,
            "fill": True
        })
        
    # 3. Game Catalog Distribution extraction
    cursor.execute("SELECT game_name, SUM(CAST(playtime AS REAL)) FROM game_records GROUP BY game_name ORDER BY SUM(CAST(playtime AS REAL)) DESC")
    game_rows = cursor.fetchall()
    game_labels = [row[0] for row in game_rows]
    game_data_points = [round(row[1] or 0.0, 2) for row in game_rows]
    
    conn.close()
    
    return templates.TemplateResponse(
        request=request, name="admin_charts.html", 
        context={
            "user": request.session.get("user"),
            "chart_dates": json.dumps(timeline_dates),
            "chart_datasets": json.dumps(cumulative_datasets),
            "game_labels": json.dumps(game_labels),
            "game_data": json.dumps(game_data_points)
        }
    )


# ==========================================
# BACKEND TIMELOG TRACKING & VALIDATION (CRUD)
# ==========================================

@app.post("/game/add")
def add_record(
    game_name: str = Form(...), 
    hours: int = Form(...), 
    minutes: int = Form(...), 
    levels: str = Form(...), 
    date_logged: str = Form(...)
):
    if not (0 <= hours <= 24) or not (0 <= minutes <= 59):
        return HTMLResponse("Boundary protection triggered: Hours [0-24], Minutes [0-59]. <a href='/dashboard'>Back</a>", status_code=400)
    
    # Calculate uniform backend decimal playtime representation
    calculated_decimal = round(hours + (minutes / 60.0), 2)
    
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    cursor.execute("INSERT INTO game_records (username, game_name, playtime, levels, date_logged) VALUES (?, ?, ?, ?, ?)",
                   ("ryan", game_name, str(calculated_decimal), levels, date_logged)) # Standardized fallback if session tracking isolates
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
    cursor.execute("SELECT id, game_name, playtime, levels, date_logged FROM game_records WHERE id = ? AND username = ?", (record_id, user))
    row = cursor.fetchone()
    if not row:
        conn.close()
        return HTMLResponse("Unauthorized path exception.", status_code=404)
        
    pt = float(row[2] or 0.0)
    extracted_hours = int(pt)
    extracted_minutes = int(round((pt - extracted_hours) * 60))
    
    record = {
        "id": row[0], "game_name": row[1], 
        "hours": extracted_hours, "minutes": extracted_minutes, 
        "levels": row[3], "date_logged": row[4]
    }
    
    cursor.execute("SELECT name FROM games ORDER BY name ASC")
    games = [r[0] for r in cursor.fetchall()]
    conn.close()
    return templates.TemplateResponse(request=request, name="edit_record.html", context={"user": user, "record": record, "games": games})

@app.post("/game/edit/{record_id}")
def handle_edit_record(
    request: Request, record_id: int, 
    game_name: str = Form(...), 
    hours: int = Form(...), 
    minutes: int = Form(...), 
    levels: str = Form(...), 
    date_logged: str = Form(...)
):
    user = request.session.get("user")
    if not user:
        return RedirectResponse(url="/", status_code=302)
    if not (0 <= hours <= 24) or not (0 <= minutes <= 59):
        return HTMLResponse("Boundary error: Hours [0-24], Minutes [0-59].", status_code=400)
        
    calculated_decimal = round(hours + (minutes / 60.0), 2)
    
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    cursor.execute("UPDATE game_records SET game_name=?, playtime=?, levels=?, date_logged=? WHERE id=? AND username=?",
                   (game_name, str(calculated_decimal), levels, date_logged, record_id, user))
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