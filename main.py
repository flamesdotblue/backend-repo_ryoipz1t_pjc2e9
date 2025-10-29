import os
from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer
from pydantic import BaseModel, EmailStr
from jose import JWTError, jwt
from passlib.context import CryptContext

from database import db, create_document
from schemas import Account

# App init
app = FastAPI(title="Learning Hub Auth API")

# CORS (allow localhost and dev previews)
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "*",
        "http://localhost:3000",
        "http://127.0.0.1:3000",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Security settings
SECRET_KEY = os.getenv("SECRET_KEY", "dev-secret-change-me")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24  # 1 day

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/signin")

# Helpers

def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)

def verify_password(plain_password: str, password_hash: str) -> bool:
    return pwd_context.verify(plain_password, password_hash)

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

async def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        if email is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception

    user = db["account"].find_one({"email": email})
    if not user:
        raise credentials_exception
    # Normalize
    user["id"] = str(user.pop("_id"))
    user.pop("password_hash", None)
    return user

# Schemas
class SignUpBody(BaseModel):
    name: Optional[str] = None
    email: EmailStr
    password: str

class SignInBody(BaseModel):
    email: EmailStr
    password: str

class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"

class MeResponse(BaseModel):
    id: str
    name: Optional[str] = None
    email: EmailStr
    is_active: bool = True

# Routes
@app.get("/")
def root():
    return {"message": "Auth backend running"}

@app.get("/test")
def test_database():
    try:
        collections = db.list_collection_names() if db else []
        return {"backend": "ok", "database": "ok" if db else "missing", "collections": collections}
    except Exception as e:
        return {"backend": "ok", "database": f"error: {str(e)[:100]}"}

@app.post("/auth/signup", response_model=TokenResponse)
def signup(body: SignUpBody):
    # Ensure unique email
    existing = db["account"].find_one({"email": body.email})
    if existing:
        raise HTTPException(status_code=400, detail="Email already registered")

    account = Account(
        name=body.name,
        email=body.email,
        password_hash=get_password_hash(body.password),
        is_active=True,
    )
    create_document("account", account)

    token = create_access_token({"sub": body.email})
    return TokenResponse(access_token=token)

@app.post("/auth/signin", response_model=TokenResponse)
def signin(body: SignInBody):
    user = db["account"].find_one({"email": body.email})
    if not user:
        raise HTTPException(status_code=400, detail="Incorrect email or password")
    if not verify_password(body.password, user.get("password_hash", "")):
        raise HTTPException(status_code=400, detail="Incorrect email or password")
    if not user.get("is_active", True):
        raise HTTPException(status_code=403, detail="User is inactive")

    token = create_access_token({"sub": user["email"]})
    return TokenResponse(access_token=token)

@app.get("/auth/me", response_model=MeResponse)
async def me(current_user: dict = Depends(get_current_user)):
    return current_user

@app.post("/auth/signout")
async def signout():
    # Stateless JWT: client should discard the token
    return {"message": "Signed out. Please remove token on client."}

if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
