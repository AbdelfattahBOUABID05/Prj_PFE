import os

class Config:
    GEMINI_API_KEY = "AIzaSyA_BqRQsgb6128Aifj0vmz420TXrU4cu3c"
    
    UPLOAD_FOLDER = 'uploads'
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024  
    
    SECRET_KEY = os.urandom(24)