import struct
import hashlib

def sha256_padding(message_length):
    """Return SHA-256 padding for a message of given length."""
    padding = b'\x80'
    padding += b'\x00' * ((56 - (message_length + 1) % 64) % 64)
    padding += struct.pack('>Q', message_length * 8)
    return padding

def length_extension_attack(original_message, original_hash, extra_data):
    """Perform length extension attack to compute new message and hash."""
    # Parse the original hash as the state
    h = struct.unpack(">8I", original_hash)

    # Length of the original message + padding
    original_message_length = len(original_message) + len(sha256_padding(len(original_message)))

    # Initialize a new SHA-256 object with the internal state from original_hash
    sha = hashlib.sha256()
    sha._h = list(h)
    sha._msglength = original_message_length * 8

    # Update SHA-256 with extra data to produce h'
    sha.update(extra_data)
    new_hash = sha.digest()

    # Construct m' by appending padding to the original message and the extra data
    new_message = original_message + sha256_padding(len(original_message)) + extra_data

    return new_message, new_hash

# Read the original message and hash
with open("message.bin", "rb") as message_file:
    original_message = message_file.read()

with open("hash.bin", "rb") as hash_file:
    original_hash = hash_file.read()

# Define the extra data to append to the message
extra_data = b"_extended_data"

# Perform the length extension attack
new_message, new_hash = length_extension_attack(original_message, original_hash, extra_data)

# Write the new message and new hash to separate files
with open("extended_message.bin", "wb") as extended_message_file:
    extended_message_file.write(new_message)

with open("extended_hash.bin", "wb") as extended_hash_file:
    extended_hash_file.write(new_hash)

print("Files created: extended_message.bin, extended_hash.bin")
