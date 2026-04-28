from itsdangerous import URLSafeTimedSerializer

# Simulate the app config
SECRET_KEY = "ma-cle-secrete-fixe-123"
SALT = "auth-token"

s = URLSafeTimedSerializer(SECRET_KEY)

# 1. Generate token
user_id = 1
token = s.dumps(user_id, salt=SALT)
print(f"Generated Token: {token}")

# 2. Verify token
try:
    decoded_id = s.loads(token, salt=SALT, max_age=86400)
    print(f"Decoded User ID: {decoded_id}")
    if decoded_id == user_id:
        print("✅ Token verification successful!")
    else:
        print("❌ Token verification failed: ID mismatch")
except Exception as e:
    print(f"❌ Token verification failed: {e}")
