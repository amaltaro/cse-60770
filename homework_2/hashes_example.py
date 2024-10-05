import hashlib


password = "notredame"

md5_hash = hashlib.md5(password.encode()).hexdigest()
sha256_hash = hashlib.sha256(password.encode()).hexdigest()

print("MD5 HASH =",md5_hash)
print("SHA256 HASH =",sha256_hash)
