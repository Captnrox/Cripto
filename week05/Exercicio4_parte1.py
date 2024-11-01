import os
import hashlib

def generate_key(length=16):
    """Generate a random key of specified length."""
    return os.urandom(length)

def compute_sha256(key, message):
    """Compute SHA-256 of key concatenated with message."""
    sha = hashlib.sha256()
    sha.update(key + message)
    return sha.digest()

# Generate secret key k and message m
key = generate_key()
message = b"original_message"

# Compute SHA-256 hash of k || m
hash_value = compute_sha256(key, message)

# Write key, message, and hash to separate files
with open("key.bin", "wb") as key_file:
    key_file.write(key)

with open("message.bin", "wb") as message_file:
    message_file.write(message)

with open("hash.bin", "wb") as hash_file:
    hash_file.write(hash_value)

print("Files created: key.bin, message.bin, hash.bin")
