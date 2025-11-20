import structlog, logging, sys, os
from app.config.settings import settings

def relative_path(path):
    try:
        cwd = os.getcwd()
        return os.path.relpath(path, cwd)
    except Exception:
        return path

def add_relative_path(logger, method_name, event_dict):
    if "pathname" in event_dict:
        event_dict["pathname"] = relative_path(event_dict["pathname"])
    return event_dict

def filter_by_log_level_factory(min_level):
    min_level = min_level.upper()
    levels = {"CRITICAL": 50, "ERROR": 40, "WARNING": 30, "INFO": 20, "DEBUG": 10}
    min_level_num = levels.get(min_level, 20)
    def processor(logger, method_name, event_dict):
        event_level = event_dict.get("level", "").upper()
        if levels.get(event_level, 0) < min_level_num:
            raise structlog.DropEvent
        return event_dict
    return processor

def configure_logging():
    log_level = settings.LOG_LEVEL if hasattr(settings, "LOG_LEVEL") else "INFO"
    numeric_level = getattr(logging, log_level, logging.INFO)
    logging.basicConfig(stream=sys.stdout, level=numeric_level)
    
    # Suppress verbose DEBUG logs from aio_pika and aiormq
    logging.getLogger("aio_pika").setLevel(logging.WARNING)
    logging.getLogger("aio_pika.robust_connection").setLevel(logging.WARNING)
    logging.getLogger("aiormq").setLevel(logging.WARNING)
    logging.getLogger("aiormq.connection").setLevel(logging.WARNING)
    
    structlog.configure(
        processors=[
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.processors.add_log_level,
            structlog.processors.CallsiteParameterAdder([
                structlog.processors.CallsiteParameter.FUNC_NAME,
                structlog.processors.CallsiteParameter.PATHNAME,
                structlog.processors.CallsiteParameter.LINENO,
                structlog.processors.CallsiteParameter.MODULE,
            ]),
            add_relative_path,
            filter_by_log_level_factory(log_level),  # <-- This line enforces the level
            structlog.dev.ConsoleRenderer()
        ]
    )
    
# Example of a custom processor to log to MongoDB  
#     import structlog, logging, sys
# from app.config.settings import settings
# from pymongo import MongoClient

# class MongoDBLogProcessor:
#     def __init__(self, uri, db_name, collection_name):
#         self.client = MongoClient(uri)
#         self.collection = self.client[db_name][collection_name]

#     def __call__(self, logger, method_name, event_dict):
#         # Insert the log event as a document
#         self.collection.insert_one(event_dict)
#         return event_dict

# def configure_logging():
#     logging.basicConfig(stream=sys.stdout, level=getattr(logging, settings.LOG_LEVEL, logging.INFO))
#     mongo_processor = MongoDBLogProcessor(
#         uri=settings.MONGO_URI,
#         db_name=settings.MONGO_DB,
#         collection_name="logs"
#     )
#     structlog.configure(
#         processors=[
#             structlog.processors.TimeStamper(fmt="iso"),
#             structlog.processors.add_log_level,
#             structlog.processors.CallsiteParameterAdder([
#                 structlog.processors.CallsiteParameter.FUNC_NAME,
#                 structlog.processors.CallsiteParameter.PATHNAME,
#                 structlog.processors.CallsiteParameter.LINENO,
#                 structlog.processors.CallsiteParameter.MODULE,
#             ]),
#             mongo_processor,  # Store log in MongoDB
#             structlog.processors.JSONRenderer(),
#         ]
#     )