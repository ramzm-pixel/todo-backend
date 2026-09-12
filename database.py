from sqlalchemy import create_engine, String, ForeignKey, or_, DateTime
from sqlalchemy.orm import sessionmaker, Session, Mapped, mapped_column, DeclarativeBase, relationship
from pydantic import BaseModel, ConfigDict, EmailStr, Field, field_validator
from datetime import date, datetime, timezone, timedelta
from typing import Optional, List
from auth import hash_password, verify_password, create_access_token
import secrets
import os
from dotenv import load_dotenv

load_dotenv()

DATABASE_URL = os.environ['DATABASE_URL']

if DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql+psycopg://", 1)
elif DATABASE_URL.startswith("postgresql://"):
    DATABASE_URL = DATABASE_URL.replace("postgresql://", "postgresql+psycopg://", 1)

engine = create_engine(DATABASE_URL)
LocalSession = sessionmaker(autocommit=False, autoflush=False, bind=engine)

class Base(DeclarativeBase):
    pass

class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(primary_key=True)
    username: Mapped[str] = mapped_column(
        String(50), nullable=False, unique=True, index=True
    )
    email: Mapped[str] = mapped_column(String(255), nullable=False, unique=True)
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)

    tasks: Mapped[List["Task"]] = relationship(
        "Task", back_populates="user", cascade="all, delete-orphan"
    )
    password_resets: Mapped[List["PasswordReset"]] = relationship(
        "PasswordReset", back_populates="user", cascade="all, delete-orphan"
    )

class Task(Base):
    __tablename__ = "tasks"

    id: Mapped[int] = mapped_column(primary_key=True)
    
    user_id: Mapped[int] = mapped_column(
        ForeignKey("users.id"), nullable=False, index=True
    )

    title: Mapped[str] = mapped_column(String(255), nullable=False)
    notes: Mapped[Optional[str]] = mapped_column(String(1000))
    due_date: Mapped[date] = mapped_column(nullable=False)
    is_done: Mapped[bool] = mapped_column(default=False, nullable=False)

    user: Mapped["User"] = relationship("User", back_populates="tasks")

class PasswordReset(Base):
    __tablename__ = "password_reset"

    id: Mapped[int] = mapped_column(primary_key=True)
    
    user_id: Mapped[int] = mapped_column(
        ForeignKey("users.id"), nullable=False, index=True
    )

    token: Mapped[str] = mapped_column(String(32), nullable=False, unique=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    used: Mapped[bool] = mapped_column(default=False, nullable=False)

    user: Mapped["User"] = relationship("User", back_populates="password_resets")

Base.metadata.create_all(bind=engine)

class TaskCreate(BaseModel):
    title: str
    notes: Optional[str] = None
    due_date: date
    is_done: bool = False


class TaskResponse(BaseModel):
    id: int
    user_id: int
    title: str
    notes: Optional[str] = None
    due_date: date
    is_done: bool

    model_config = ConfigDict(from_attributes=True)


class UserCreate(BaseModel):
    username: str = Field(min_length=3)
    email: EmailStr
    password: str = Field(min_length=8)
    confirm_password: str

    @field_validator("password")
    @classmethod
    def password_complexity(cls, value: str) -> str:
        if not any(c.isupper() for c in value):
            raise ValueError("Password must contain at least one uppercase letter.")
        if not any(c.isdigit() for c in value):
            raise ValueError("Password must contain at least one number.")
        return value


class UserLogin(BaseModel):
    username_or_email: str
    password: str

class PasswordResetRequest(BaseModel):
    email: EmailStr

class NewPasswordRequest(BaseModel):
    new_password: str = Field(min_length=8)
    confirm_password: str

    @field_validator("new_password")
    @classmethod
    def password_complexity(cls, value: str) -> str:
        if not any(c.isupper() for c in value):
            raise ValueError("Password must contain at least one uppercase letter.")
        if not any(c.isdigit() for c in value):
            raise ValueError("Password must contain at least one number.")
        return value


def create_account(db: Session, user: UserCreate):

    if not user.username or not user.email or not user.password or not user.confirm_password:
        raise ValueError("Please fill in all fields")

    if user.password != user.confirm_password:
        raise ValueError("Passwords do not match")


    existing_user = (
        db.query(User)
        .filter(or_(
                User.username == user.username,
                User.email == user.email
            )
        ).first()
    )

    if existing_user:
        raise ValueError("Email or Username already in use")

    hashed_password = hash_password(user.password)

    new_user = User(
        username=user.username, email=user.email, password_hash=hashed_password
    )

    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    token = create_access_token(new_user.id)

    return {"access_token": token, "token_type": "bearer"}

def login_user(db: Session, credentials: UserLogin) -> dict:

    if not credentials.username_or_email or not credentials.password:
        raise ValueError("Please enter valid credentials.")
    
    user = (
        db.query(User)
        .filter(
            or_(
                User.username == credentials.username_or_email,
                User.email == credentials.username_or_email,
            )
        ).first()
    )

    if not user or not verify_password(credentials.password, user.password_hash):
        raise ValueError("Invalid username or password.")

    token = create_access_token(user.id)
    return {"access_token": token, "token_type": "bearer"}

def create_task(db: Session, user_id: int, task_data: TaskCreate) -> TaskResponse:

    if (not task_data.title or not task_data.due_date):
        raise ValueError("Please fill in all fields")

    new_task = Task(
        user_id=user_id,
        title=task_data.title,
        notes=task_data.notes,
        due_date=task_data.due_date,
        is_done=task_data.is_done,
    )
    db.add(new_task)
    db.commit()
    db.refresh(new_task)
    return TaskResponse.model_validate(new_task)


def get_tasks(db: Session, user_id: int) -> List[TaskResponse]:
    tasks = db.query(Task).filter(Task.user_id == user_id).all()
    return [TaskResponse.model_validate(task) for task in tasks]

def update_task_status(db: Session, user_id: int, task_id: int, updated_status: bool) -> TaskResponse:
    task = db.query(Task).filter(Task.id == task_id, Task.user_id == user_id).first()

    if not task:
        raise ValueError("Invalid task ID")

    task.is_done = updated_status
    db.commit()
    db.refresh(task)

    return TaskResponse.model_validate(task)


def delete_task(db: Session, user_id: int, task_id: int) -> None:
    task = db.query(Task).filter(Task.id == task_id, Task.user_id == user_id).first()
    
    if not task:
        raise ValueError("Invalid task ID")

    db.delete(task)
    db.commit()

def create_reset_password_link(db: Session, email: str) -> str:
    if not email:
        raise ValueError("Please enter a valid email")

    user = db.query(User).filter(
        User.email == email,
    ).first()

    if not user:
        raise ValueError("Email doesn't exist")

    exists = True

    while exists:
        token = secrets.token_urlsafe(16)
        exists = db.query(PasswordReset).filter(
            PasswordReset.token == token
        ).first()

    passwordreset = PasswordReset(
        user_id = user.id,
        token = token, # type: ignore
        expires_at = datetime.now(timezone.utc) + timedelta(minutes=15)
    )

    db.add(passwordreset)
    db.commit()
    db.refresh(passwordreset)

    return passwordreset.token

def update_password(db: Session, new_password: str, confirm_password: str, token: str) -> None:
    if not new_password or not confirm_password:
        raise ValueError("Please fill all fields")

    if new_password != confirm_password:
        raise ValueError("Passwords do not match")

    passwordreset_target = db.query(PasswordReset).filter(
        PasswordReset.token == token
    ).first()

    if not passwordreset_target:
        raise ValueError("Token not found")

    if passwordreset_target.expires_at < datetime.now(timezone.utc) or passwordreset_target.used:
        raise ValueError("Expired link. Please request another one")

    user = db.query(User).filter(
        User.id == passwordreset_target.user_id
    ).first()

    if not user:
        raise ValueError("User not found")

    password_hash = hash_password(new_password)
    user.password_hash = password_hash
    passwordreset_target.used = True
    db.commit()


def get_db():
    db = LocalSession()
    try:
        yield db
    finally:
        db.close()