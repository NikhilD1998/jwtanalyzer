import jwt

with open("private.pem", "rb") as f:
    private_key = f.read()

payload = {
    "sub": "1234567890",
    "name": "John Doe",
    "admin": True
}

token = jwt.encode(
    payload,
    private_key,
    algorithm="RS256"
)

print(token)