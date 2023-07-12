from datetime import datetime, timedelta
from pathlib import Path
from fastapi import HTTPException, status,Depends,Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from passlib.context import CryptContext
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import jwt,JWTError
from models.usertable import User
from config import Config
from typing import Optional
from sqlalchemy.orm.session import Session
from jwt import decode as jwt_decode
from connections import get_db
from jwt.exceptions import ExpiredSignatureError, InvalidTokenError

class JWTBearer(HTTPBearer):

    def __init__(self, auto_error: bool = True):
        super(JWTBearer, self).__init__(auto_error=auto_error)

    async def __call__(self, request: Request):
        credentials: HTTPAuthorizationCredentials = await super(JWTBearer, self).__call__(request)
        if credentials:
            if not credentials.scheme == "Bearer":
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail={"status": "Forbidden", "message": "Invalid authentication schema."},
                )
            if not self.verify_jwt(credentials.credentials):
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail={"status": "Forbidden", "message": "Invalid token or expired token."},
                )
            return credentials.credentials
        else:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail={"status": "Forbidden", "message": "Invalid authorization code."},
            )

    @staticmethod
    def verify_jwt(jwt_token: str):
        try:
            jwt_decode(jwt_token, Config.SECRET_KEY, algorithms=[Config.HASH_ALGORITHM])
            return True
        except JWTError:
            return False

oauth2_scheme = JWTBearer()

async def authenticate_token(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={'WWW-Authenticate': 'Bearer'},
    )
    try:
        payload = jwt_decode(token, Config.SECRET_KEY, algorithms=[Config.HASH_ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
        return username
    except JWTError:
        raise credentials_exception

def get_access_token(user: User, password: str) -> str:
    if not CryptContext(schemes=["sha256_crypt"], deprecated="auto").verify(
        password, user.password
    ):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect password",
        )

    access_token = jwt.encode(
        {
            "sub": user.username,
            "exp": datetime.utcnow()
            + timedelta(minutes=Config.ACCESS_TOKEN_EXPIRE_MINUTES),
        },
        Config.SECRET_KEY,
        algorithm=Config.HASH_ALGORITHM,
    )

    return access_token

def verify_password(password: str, hashed_password: str) -> bool:
    return CryptContext(schemes=["sha256_crypt"], deprecated="auto").verify(password, hashed_password)
