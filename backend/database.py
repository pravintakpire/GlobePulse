import os
import json
import logging
from google.cloud import firestore

# Setup Logger
logger = logging.getLogger("Database")

# Setup Firestore Client if environment is present
db = None
if "GOOGLE_APPLICATION_CREDENTIALS" in os.environ or "K_SERVICE" in os.environ or "USE_FIRESTORE" in os.environ:
    try:
        db = firestore.Client(project="globepulse-demo")
        logger.info("Firestore Client initialized successfully.")
    except Exception as e:
        logger.error(f"Failed to initialize Firestore Client: {e}")
        db = None
else:
    logger.info("Firestore Client initialization skipped (local environment mode).")

def get_users_file_path() -> str:
    """Resolves the path to the local users.json file."""
    if os.path.exists('users.json'):
        return 'users.json'
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    return os.path.join(base_dir, 'users.json')

def load_users() -> dict:
    """Fetches all users from Firestore if active, otherwise loads from local users.json."""
    users = {}
    
    # 1. Try Firestore if configured
    if db is not None:
        try:
            docs = db.collection("users").stream()
            for doc in docs:
                users[doc.id] = doc.to_dict()
            logger.info("Loaded users from Firestore.")
            return users
        except Exception as e:
            logger.error(f"Error loading users from Firestore: {e}")
            
    # 2. Fallback to local users.json
    filepath = get_users_file_path()
    if os.path.exists(filepath):
        try:
            with open(filepath, 'r') as f:
                users = json.load(f)
            logger.info(f"Loaded users from local file: {filepath}")
        except Exception as e:
            logger.error(f"Error loading local users: {e}")
            
    return users

def save_users(users: dict):
    """Saves user records to Firestore if active, and always writes locally to users.json."""
    # 1. Try Firestore if configured
    if db is not None:
        try:
            batch = db.batch()
            for email_key, data in users.items():
                doc_ref = db.collection("users").document(email_key)
                batch.set(doc_ref, data)
            batch.commit()
            logger.info("Saved users to Firestore successfully.")
        except Exception as e:
            logger.error(f"Error saving users to Firestore: {e}")
            
    # 2. Always write to local users.json
    try:
        filepath = get_users_file_path()
        dir_name = os.path.dirname(filepath)
        if dir_name:
            os.makedirs(dir_name, exist_ok=True)
        with open(filepath, 'w') as f:
            json.dump(users, f, indent=4)
        logger.info(f"Saved users to local file: {filepath}")
    except Exception as e:
        logger.error(f"Error saving users to local file: {e}")

def load_all_watchlist_tickers() -> list:
    """Compiles all unique watchlist tickers from users, falling back to local users.json."""
    default_tickers = ["Tesla", "Apple", "Google", "Microsoft", "Nvidia", "Amazon"]
    
    users = load_users()
    if not users:
        return default_tickers
        
    try:
        tickers = set()
        for email_key, data in users.items():
            watchlist_val = data.get("watchlist", "")
            if watchlist_val:
                if isinstance(watchlist_val, list):
                    for symbol in watchlist_val:
                        symbol = symbol.strip()
                        if symbol:
                            tickers.add(symbol)
                else:
                    for symbol in watchlist_val.split(','):
                        symbol = symbol.strip()
                        if symbol:
                            tickers.add(symbol)
                            
        if not tickers:
            return default_tickers
            
        return sorted(list(tickers))
    except Exception as e:
        logger.error(f"Error compiling watchlist: {e}")
        return default_tickers
