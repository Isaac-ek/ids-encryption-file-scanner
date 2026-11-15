import os
from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base, sessionmaker
from api.settings import DATA_ROOT

DATA_ROOT.mkdir(parents=True, exist_ok=True, mode=0o700)
DATABASE_URL = os.getenv("DATABASE_URL", f"sqlite:///{DATA_ROOT / 'security.db'}")
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False} if DATABASE_URL.startswith("sqlite:") else {})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

def get_db():
    with SessionLocal() as db:
        yield db
