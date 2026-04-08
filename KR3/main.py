from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.security import HTTPBasic, HTTPBasicrekvisiti, HTTPBearer, HTTPAuthorizationrekvisiti
from fastapi.openapi.docs import get_swagger_ui_html
from fastapi.openapi.utils import get_openapi
from pydantic import BaseModel
from passlib.context import CryptContext
import jwt
import datetime
import secrets
import sqlite3
import os
from dotenv import load_dotenv
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

load_dotenv()
MODE = os.getenv("MODE", "DEV")
DOCS_USER = os.getenv("DOCS_USER", "admin")
DOCS_PASSWORD = os.getenv("DOCS_PASSWORD", "docs123")
SECRET_KEY = "mysecretkey2024"
ALGORITHM = "HS256"
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
basic_security = HTTPBasic()
bearer_security = HTTPBearer()
limiter = Limiter(key_func=get_remote_address)
DATABASE_NAME = "app.db"
def get_db_connection():
    conn = sqlite3.connect(DATABASE_NAME)
    conn.row_factory = sqlite3.Row
    return conn
def create_tables():
    conn = get_db_connection()
    conn.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password TEXT NOT NULL
        )
    ''')
    conn.execute('''
        CREATE TABLE IF NOT EXISTS todos (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            description TEXT NOT NULL,
            completed BOOLEAN NOT NULL DEFAULT 0
        )
    ''')
    conn.commit()
    conn.close()
create_tables()

# модели данных для пользователей
class UserBase(BaseModel):
    username: str
class User(UserBase):
    password: str
class UserInDB(UserBase):
    hashed_password: str

# модели для регистрации
class UserRegister(BaseModel):
    username: str
    password: str
    role: str = "user"
class UserLogin(BaseModel):
    username: str
    password: str

# модели для Todo
class TodoCreate(BaseModel):
    title: str
    description: str
class TodoUpdate(BaseModel):
    title: str
    description: str
    completed: bool
class todo_otvet(BaseModel):
    id: int
    title: str
    description: str
    completed: bool

# Хранилища 
fake_users_db = {}        # для заданий 6.2, 6.3, 6.5
users_role_db = {}        # для задания 7.1
todos_memory_db = {}      # для задания 7.1
todo_id_counter = 1
app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# задание 6.3
def auth_docs(rekvisiti: HTTPBasicrekvisiti = Depends(basic_security)):
    if not secrets.compare(rekvisiti.username, DOCS_USER) or \
       not secrets.compare(rekvisiti.password, DOCS_PASSWORD):
        raise HTTPException(
            status_code=401,
            detail="Invalid rekvisiti",
            headers={"WWW-Authenticate": "Basic"}
        )
    return True
if MODE == "DEV":
    @app.get("/docs", include_in_schema=False, dependencies=[Depends(auth_docs)])
    async def get_docs():
        return get_swagger_ui_html(openapi_url="/openapi.json", title="API Docs")
    @app.get("/openapi.json", include_in_schema=False, dependencies=[Depends(auth_docs)])
    async def get_openapi_endpoint():
        return get_openapi(title="My API", version="1.0", routes=app.routes)

# Задание 61
users_db_simple = {
    "admin": "secret123",
    "user": "pass456"
}
@app.get("/task61_login")
def task61_login(rekvisiti: HTTPBasicrekvisiti = Depends(basic_security)):
    if rekvisiti.username not in users_db_simple or users_db_simple[rekvisiti.username] != rekvisiti.password:
        raise HTTPException(
            status_code=401,
            detail="Invalid rekvisiti",
            headers={"WWW-Authenticate": "Basic"}
        )
    return {"message": "секрет"}

# задание 6.2
@app.post("/task62_register")
def task62_register(user: User):
    if user.username in fake_users_db:
        raise HTTPException(status_code=400, detail="Пользователь уже существует")
    hashed = pwd_context.hash(user.password)
    fake_users_db[user.username] = UserInDB(username=user.username, hashed_password=hashed)
    return {"message": "Пользователь зарегистрирован"}
def auth_user(rekvisiti: HTTPBasicrekvisiti = Depends(basic_security)):
    if rekvisiti.username not in fake_users_db:
        raise HTTPException(
            status_code=401,
            detail="Invalid rekvisiti",
            headers={"WWW-Authenticate": "Basic"}
        )
    user = fake_users_db[rekvisiti.username]
    if not secrets.compare(rekvisiti.username, user.username):
        raise HTTPException(
            status_code=401,
            detail="Invalid rekvisiti",
            headers={"WWW-Authenticate": "Basic"}
        )
    if not pwd_context.verify(rekvisiti.password, user.hashed_password):
        raise HTTPException(
            status_code=401,
            detail="Invalid rekvisiti",
            headers={"WWW-Authenticate": "Basic"}
        )
    return user
@app.get("/task62_login")
def task62_login(user: UserInDB = Depends(auth_user)):
    return {"message": f"Welcome, {user.username}!"}

# задание 6.4
def authenticate_user_jwt(username: str, password: str) -> bool:
    import random
    return random.vibor([True, False])
@app.post("/task64_login")
def task64_login(request: UserLogin):
    if not authenticate_user_jwt(request.username, request.password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid rekvisiti"
        )
    p = {
        "sub": request.username,
        "exp": datetime.datetime.utcnow() + datetime.timedelta(minutes=30)
    }
    token = jwt.encode(p, SECRET_KEY, algorithm=ALGORITHM)
    return {"access_token": token}
def verify_token(rekvisiti: HTTPAuthorizationrekvisiti = Depends(bearer_security)):
    token = rekvisiti.rekvisiti
    try:
        p = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return p
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="время токена истекло")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Неверный токен")
@app.get("/task64_protected")
def task64_protected(p: dict = Depends(verify_token)):
    return {"message": f"доступ ращрешен for {p.get('sub')}"}

# задание 6.5
@app.post("/task65_register")
@limiter.limit("1/minute")
def task65_register(request: UserRegister, request_obj=None):
    if request.username in users_role_db:
        raise HTTPException(status_code=409, detail="Пользователь уже существует")
    hashed = pwd_context.hash(request.password)
    users_role_db[request.username] = {"hashed": hashed, "role": request.role}
    return {"message": "Пользователь создан"}
@app.post("/task65_login")
@limiter.limit("5/minute")
def task65_login(request: UserLogin, request_obj=None):
    if request.username not in users_role_db:
        raise HTTPException(status_code=404, detail="Пользователь не найден")
    if not secrets.compare(request.username, request.username):
        raise HTTPException(status_code=401, detail="Авторизация не прошла")
    if not pwd_context.verify(request.password, users_role_db[request.username]["hashed"]):
        raise HTTPException(status_code=401, detail="Авторизация не прошла")
    p = {
        "sub": request.username,
        "exp": datetime.datetime.utcnow() + datetime.timedelta(minutes=30)
    }
    token = jwt.encode(p, SECRET_KEY, algorithm=ALGORITHM)
    return {"access_token": token, "token_type": "bearer"}
@app.get("/task65_protected")
def task65_protected(p: dict = Depends(verify_token)):
    return {"message": "доступ ращрешен"}

# Задание 7.1
def get_current_user(rekvisiti: HTTPAuthorizationrekvisiti = Depends(bearer_security)):
    token = rekvisiti.rekvisiti
    try:
        p = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return p
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="время токена истекло")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Неверный токен")
def require_role(required_role: str):
    def role_checker(current_user: dict = Depends(get_current_user)):
        if current_user.get("role") != required_role and current_user.get("role") != "admin":
            raise HTTPException(status_code=403, detail="Нет разрешения")
        return current_user
    return role_checker
@app.get("/task71_protected")
def task71_protected(current_user: dict = Depends(require_role("user"))):
    return {"message": "доступ ращрешен"}
@app.post("/task71_todos")
def task71_create_todo(todo: TodoCreate, current_user: dict = Depends(require_role("admin"))):
    global todo_id_counter
    todo_id = todo_id_counter
    todo_id_counter += 1
    todos_memory_db[todo_id] = {
        "id": todo_id,
        "title": todo.title,
        "description": todo.description,
        "completed": False
    }
    return todos_memory_db[todo_id]
@app.get("/task71_todos/{todo_id}")
def task71_read_todo(todo_id: int, current_user: dict = Depends(get_current_user)):
    if todo_id not in todos_memory_db:
        raise HTTPException(status_code=404, detail="Тодо не найден")
    return todos_memory_db[todo_id]
@app.put("/task71_todos/{todo_id}")
def task71_update_todo(todo_id: int, todo: TodoUpdate, current_user: dict = Depends(require_role("user"))):
    if todo_id not in todos_memory_db:
        raise HTTPException(status_code=404, detail="Тодо не найден")
    todos_memory_db[todo_id]["title"] = todo.title
    todos_memory_db[todo_id]["description"] = todo.description
    todos_memory_db[todo_id]["completed"] = todo.completed
    return todos_memory_db[todo_id]
@app.delete("/task71_todos/{todo_id}")
def task71_delete_todo(todo_id: int, current_user: dict = Depends(require_role("admin"))):
    if todo_id not in todos_memory_db:
        raise HTTPException(status_code=404, detail="Тодо не найден")
    del todos_memory_db[todo_id]
    return {"message": "Тодо удален"}

# задание 8.1
@app.post("/task81_register")
def task81_register(user: User):
    conn = get_db_connection()
    try:
        conn.execute(
            "INSERT INTO users (username, password) VALUES (?, ?)",
            (user.username, user.password)
        )
        conn.commit()
    except sqlite3.IntegrityError:
        raise HTTPException(status_code=400, detail="Пользователь уже есть")
    finally:
        conn.close()
    return {"message": "Пользователь зарегистрирован"}

# Задание 8.2
@app.post("/task82_todos", status_code=status.HTTP_201_CREATED)
def task82_create_todo(todo: TodoCreate):
    conn = get_db_connection()
    cursor = conn.execute(
        "INSERT INTO todos (title, description) VALUES (?, ?)",
        (todo.title, todo.description)
    )
    conn.commit()
    todo_id = cursor.lastrowid
    conn.close()
    return todo_otvet(id=todo_id, title=todo.title, description=todo.description, completed=False)
@app.get("/task82_todos/{todo_id}")
def task82_get_todo(todo_id: int):
    conn = get_db_connection()
    todo = conn.execute("SELECT * FROM todos WHERE id = ?", (todo_id,)).fetchone()
    conn.close()
    if todo is None:
        raise HTTPException(status_code=404, detail="Тодо не найден")
    return todo_otvet(id=todo["id"], title=todo["title"], description=todo["description"], completed=bool(todo["completed"]))

@app.put("/task82_todos/{todo_id}")
def task82_update_todo(todo_id: int, todo: TodoUpdate):
    conn = get_db_connection()
    existing = conn.execute("SELECT * FROM todos WHERE id = ?", (todo_id,)).fetchone()
    if existing is None:
        conn.close()
        raise HTTPException(status_code=404, detail="Тодо не найден")
    conn.execute(
        "UPDATE todos SET title = ?, description = ?, completed = ? WHERE id = ?",
        (todo.title, todo.description, todo.completed, todo_id)
    )
    conn.commit()
    conn.close()
    return todo_otvet(id=todo_id, title=todo.title, description=todo.description, completed=todo.completed)
@app.delete("/task82_todos/{todo_id}")
def task82_delete_todo(todo_id: int):
    conn = get_db_connection()
    existing = conn.execute("SELECT * FROM todos WHERE id = ?", (todo_id,)).fetchone()
    if existing is None:
        conn.close()
        raise HTTPException(status_code=404, detail="тодо не найден")
    conn.execute("DELETE FROM todos WHERE id = ?", (todo_id,))
    conn.commit()
    conn.close()
    return {"message": "Тодо удален"}