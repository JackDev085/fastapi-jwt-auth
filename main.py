from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel
from datetime import datetime, timedelta

# Configurações gerais
SECRET_KEY = "yxb7zu&zyai9pf4_sy&vpizllx14+$(s$xs^ohx)+)u-c8$w$o"  # Substitua por um segredo seguro
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# Contexto de hash
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Simulação de "banco de dados"
fake_users_db = {
    "jackson": {
        "username": "jackson",
        "full_name": "Jackson Silva",
        "email": "jackson@example.com",
        "hashed_password": "$2b$12$eIXvlAe09k6T8JfN5m9fYu4.Ou27oxuN9SO5Mj3AZW.iIVF.dfeBi",  # senha: "senha123"
        "disabled": False,
    }
}

# Funções auxiliares
def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def get_user(db, username: str):
    user = db.get(username)
    if user:
        return UserInDB(**user)

def authenticate_user(fake_db, username: str, password: str):
    user = get_user(fake_db, username)
    if not user or not verify_password(password, user.hashed_password):
        return False
    return user

def create_access_token(data: dict, expires_delta: timedelta | None = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

# Inicialize o FastAPI
app = FastAPI()

# Dependência OAuth2
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# Modelos de dados
class Token(BaseModel):
    access_token: str
    token_type: str

class User(BaseModel):
    username: str
    email: str | None = None
    full_name: str | None = None
    disabled: bool | None = None

class UserInDB(User):
    hashed_password: str

# Rota para gerar o token de acesso
@app.post("/token", response_model=Token)
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    print(f"Form Data: {form_data.username}, {form_data.password}")

    user = authenticate_user(fake_users_db, form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Credenciais inválidas",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}

# Rota para acessar informações do usuário autenticado
@app.get("/users/me", response_model=User)
async def read_users_me(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Não foi possível validar as credenciais",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    user = get_user(fake_users_db, username)
    if user is None:
        raise credentials_exception
    return user

# Gerar um hash para a senha "senha123" para garantir a correta validação
hashed_password = pwd_context.hash("senha123")
fake_users_db["jackson"]["hashed_password"] = hashed_password
