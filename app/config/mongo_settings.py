# Add your MongoDB Atlas URI and DB name here
from pymongo import MongoClient
from app.config.settings import settings
import structlog

logger = structlog.get_logger(__name__)

# Global MongoDB client instance
mongo_client = None

def connect_db():
	global mongo_client
	if mongo_client is None:
		mongo_client = MongoClient(f"mongodb+srv://{settings.MONGO_USER}:{settings.MONGO_PASSWORD}{settings.MONGO_URI}")
		logger.info("Connected to MongoDB Atlas.")
		logger.debug("MongoDB Client Details:", client=str(mongo_client))
		logger.debug("MongoDB URI:", uri=f"mongodb+srv://{settings.MONGO_USER}:{settings.MONGO_PASSWORD}{settings.MONGO_URI}")
	return mongo_client

def disconnect_db():
	global mongo_client
	if mongo_client is not None:
		mongo_client.close()
		mongo_client = None
