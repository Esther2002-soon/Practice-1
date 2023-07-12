from fastapi import FastAPI,APIRouter, Depends, Body, HTTPException, status,Response,Header
from jwt import encode as jwt_encode
from datetime import datetime, timedelta,date
from models.usertable import User
from sqlalchemy.orm.session import Session
from typing import Annotated,List
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from passlib.context import CryptContext
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from enums import Response
from config import Config
from connections import get_db
from utility import get_access_token,authenticate_token,verify_password
from fastapi.responses import PlainTextResponse,JSONResponse

origins=[
    "http://localhost:3000"
]
mycrypt = CryptContext(schemes=["sha256_crypt"], deprecated="auto")
def create_password_digest(password):
    return mycrypt.hash(password)

app = FastAPI()

app.add_middleware(
        CORSMiddleware,
        allow_origins=origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"]
    )
@app.post(
    "/login",
    tags=["Login"],
    summary="return jwt",
    description="passing correct username and password of account will return jwt",
    responses={200: Response.OK.doc, 401: Response.UNAUTHORIZED.doc},
)
def get_jwt(
    username: str = Body(),
    password: str = Body(),
    session: Session = Depends(get_db),
):
    user: User = (
        session.query(User).filter(User.username == username).first()
    )
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User: " + username + " not found.",
        )
    jwt_token = get_access_token(user, password)
    user.last_login = datetime.utcnow()
    session.commit()
    return PlainTextResponse(jwt_token, 200)

@app.post(
    "/signup/",
    tags=["Signup"],
    summary="Create new user",
    description="Add new user to database",
    responses={200: Response.OK.doc, 400: Response.BAD_REQUEST.doc},
)
def user_signup(
    username: str = Body(),
    password: str = Body(),
    birthday: date = Body(),
    session: Session = Depends(get_db),
):
    existing_user = session.query(User).filter(User.username == username).first()
    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="User: " + username + " already exists.",
        )
    user = User(
        username=username,
        password=create_password_digest(password),
        birthday=birthday,
        create_time=datetime.utcnow(),
    )
    session.add(user)
    session.commit()
    return PlainTextResponse("User created", 200)

@app.delete(
    "/user/",
    tags=["User"],
    summary="Delete user",
    description="Delete user based on authenticated user",
    responses={200: Response.OK.doc, 400: Response.BAD_REQUEST.doc,401: Response.UNAUTHORIZED.doc},
)
def delete_user(
    session: Session = Depends(get_db),
    current_user: str = Depends(authenticate_token),

):
    user: User = session.query(User).filter(User.username == current_user).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="User: " + current_user + " does not exist.",
        )

    session.delete(user)
    session.commit()
    return PlainTextResponse("User deleted.", 200)

class UserBase(BaseModel):
    username: str
    birthday: date
    create_time: datetime
    last_login: datetime

@app.get( 
    "/user/",
    tags=["User"],
    summary="Return user data",
    description="Return user based on authenticated user")
async def read_user_data(session: Session = Depends(get_db), current_user: str = Depends(authenticate_token)):
    user = session.query(User).filter(User.username == current_user).first()
    if user:
        user_data = UserBase(username=user.username, birthday=user.birthday,create_time=user.create_time,last_login=user.last_login)
        return user_data
    else:
        return {"message": "User not found"}


class UpdateUserData(BaseModel):
    username: str
    password: str
    birthday: date

@app.patch(
    "/user/",
    tags=["User"],
    summary="Update data",
    description="Update data of authenticated user")
async def update_user_data(
    updated_data: UpdateUserData,
    session: Session = Depends(get_db),
    current_user: str = Depends(authenticate_token)
):
    user:User = session.query(User).filter(User.username == current_user).first()
    
    user.username = updated_data.username
    user.password = create_password_digest(updated_data.password)
    user.birthday = updated_data.birthday
    session.commit()
    return PlainTextResponse("User data updated successfully.", 200)