from typing import List
from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session

from auth import get_current_user_id
from database import (
    NewPasswordRequest,
    PasswordResetRequest,
    TaskCreate,
    TaskResponse,
    UserCreate,
    UserLogin,
    create_account,
    create_reset_password_link,
    create_task,
    delete_task,
    get_db,
    get_tasks,
    login_user,
    update_password,
    update_task_status
)

app = FastAPI()

origins = [
    "http://localhost:5500",
    "http://127.0.0.1:5500",
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_methods=["GET", "POST", "PATCH", "DELETE"],
    allow_headers=["Content-Type", "Authorization"],
)

@app.post("/register", status_code=status.HTTP_201_CREATED)
def register(user: UserCreate, db: Session = Depends(get_db)):
    try:
        return create_account(db, user)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.post("/login")
def login(user: UserLogin, db: Session = Depends(get_db)):
    try:
        return login_user(db, user)
    except ValueError as e:
        raise HTTPException(status_code=401, detail=str(e))

@app.post("/tasks", response_model=TaskResponse, status_code=status.HTTP_201_CREATED)
def add_task(task: TaskCreate, db: Session = Depends(get_db), current_user_id: int = Depends(get_current_user_id)):
    try:
        return create_task(db, current_user_id, task)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.get("/tasks", response_model=List[TaskResponse])
def read_tasks(db: Session = Depends(get_db), current_user_id: int = Depends(get_current_user_id)):
    return get_tasks(db, current_user_id)

@app.patch("/tasks/{task_id}", response_model=TaskResponse, status_code=status.HTTP_200_OK)
def update_status(new_status: bool, task_id: int, db: Session = Depends(get_db), current_user_id: int = Depends(get_current_user_id)):
    try:
        return update_task_status(db, current_user_id, task_id, new_status)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))

@app.delete("/tasks/{task_id}", status_code=status.HTTP_204_NO_CONTENT)
def remove_task(task_id: int, db: Session = Depends(get_db), current_user_id: int = Depends(get_current_user_id)):
    try:
        return delete_task(db, current_user_id, task_id)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))

@app.post("/forgot-password", status_code=status.HTTP_204_NO_CONTENT)
def forgot_password(request: PasswordResetRequest, db: Session = Depends(get_db)):
    try:
        print(create_reset_password_link(db, request.email))
    except ValueError as e:
        message = str(e)
        if message == "Please enter a valid email":
            raise HTTPException(status_code=400, detail=message)
        print(message)

@app.patch("/reset-password/{token}", status_code=status.HTTP_204_NO_CONTENT)
def reset_password(request: NewPasswordRequest, token: str, db: Session = Depends(get_db)):
    try:
        return update_password(db, request.new_password, request.confirm_password, token)
    except ValueError as e:
        message = str(e)
        if message in ("Please fill all fields", "Passwords do not match"):
            raise HTTPException(status_code=400, detail=message)
        elif message in ("Token not found", "User not found"):
            raise HTTPException(status_code=404, detail=message)
        else:
            raise HTTPException(status_code=401, detail=message)