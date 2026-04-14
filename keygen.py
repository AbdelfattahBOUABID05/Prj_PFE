from cryptography.fernet import Fernet
k = Fernet.generate_key()
f = Fernet(k)
e = f.encrypt(b"NgumnevuZvQikBRwRHur5zTLNgumnevuZvQikBRwRHur5zTL")
print(f"FERNET_KEY={k.decode()}")
print(f"ENCRYPTED_REMOVEBG_KEY={e.decode()}")
