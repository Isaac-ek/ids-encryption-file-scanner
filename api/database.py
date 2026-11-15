import os
from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base, sessionmaker
from api.settings import DATA_ROOT

DATA_ROOT.mkdir(parents=True, exist_ok=True, mode=0o700)
DATABASE_URL = os.getenv("DATABASE_URL", f"sqlite:///{DATA_ROOT / 'security.db'}")
if DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = "postgresql+psycopg2://" + DATABASE_URL.removeprefix("postgres://")
elif DATABASE_URL.startswith("postgresql://"):
    DATABASE_URL = "postgresql+psycopg2://" + DATABASE_URL.removeprefix("postgresql://")
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False} if DATABASE_URL.startswith("sqlite:") else {"connect_timeout": 10}, pool_pre_ping=True, pool_recycle=300)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

def get_db():
    with SessionLocal() as db:
        yield db
