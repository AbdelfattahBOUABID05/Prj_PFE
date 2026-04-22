import os
from cryptography.fernet import Fernet
from dotenv import load_dotenv

load_dotenv()

# Key for encryption/decryption
# Clé pour le cryptage/décryptage
ENCRYPTION_KEY = os.getenv("FERNET_KEY")

if not ENCRYPTION_KEY:
    # Proactive generation of a key if it doesn't exist
    # Génération proactive d'une clé si elle n'existe pas
    ENCRYPTION_KEY = Fernet.generate_key().decode()
    print(f"ATTENTION: No FERNET_KEY found in .env. Generated one: {ENCRYPTION_KEY}")

cipher_suite = Fernet(ENCRYPTION_KEY.encode())

def encrypt_data(data: str) -> str:
    """Encrypts a string into a token"""
    """Crypte une chaîne en un jeton"""
    if not data:
        return ""
    return cipher_suite.encrypt(data.encode()).decode()

def decrypt_data(token: str) -> str:
    """Decrypts a token back into a string"""
    """Décrypte un jeton en une chaîne"""
    if not token:
        return ""
    try:
        return cipher_suite.decrypt(token.encode()).decode()
    except Exception as e:
        print(f"Decryption error: {e}")
        return ""
