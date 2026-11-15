import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from api.database import engine, Base
# Import models so they register on Base.metadata
from api.models import DBUser, DBRule, DBAuditLog, DBThreatAlert

def init_db():
    print("Creating database tables...")
    Base.metadata.create_all(bind=engine)
    print("Database tables created successfully!")

if __name__ == "__main__":
    init_db()
