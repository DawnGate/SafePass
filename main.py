from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os
from dotenv import load_dotenv
import base64
import sys

# Load environment variables from the .env file
load_dotenv()

# Function to derive a key from the password


def derive_key(password: str, salt: bytes) -> bytes:
    # PBKDF2 key derivation function
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

# Function to encode (encrypt) the input with password


def encode(input_text: str, password: str) -> str:
    # Generate a random salt
    salt = os.urandom(16)
    # Derive the key from the password and salt
    key = derive_key(password, salt)

    # Generate a random IV (Initialization Vector) for AES encryption
    iv = os.urandom(16)

    # Set up AES encryption in CBC mode
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv),
                    backend=default_backend())
    encryptor = cipher.encryptor()

    # Make sure the input length is a multiple of the block size (16 bytes)
    padded_input = input_text + (16 - len(input_text) %
                                 16) * ' '  # Padding with spaces

    # Encrypt the input
    encrypted = encryptor.update(padded_input.encode()) + encryptor.finalize()

    # Combine salt, IV, and encrypted data
    encrypted_data = salt + iv + encrypted

    # Return the encoded data as a base64 string
    return base64.b64encode(encrypted_data).decode()

# Function to decode (decrypt) the encoded string with password


def decode(encoded_text: str, password: str) -> str:
    # Decode the base64 encoded data
    encrypted_data = base64.b64decode(encoded_text)

    # Extract the salt, IV, and encrypted content
    salt = encrypted_data[:16]
    iv = encrypted_data[16:32]
    encrypted_content = encrypted_data[32:]

    # Derive the key from the password and salt
    key = derive_key(password, salt)

    # Set up AES decryption in CBC mode
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv),
                    backend=default_backend())
    decryptor = cipher.decryptor()

    # Decrypt the content
    decrypted = decryptor.update(encrypted_content) + decryptor.finalize()

    # Remove padding (spaces)
    return decrypted.decode().rstrip()


# Main function for interaction
if __name__ == "__main__":
    # Get the password from the .env file
    password = os.getenv('PASSWORD')

    # Check if password exists in the .env file
    if password is None:
        print("Error: No password found in .env file.")
        sys.exit(1)  # Exit the program with an error code

    # Ask user for an option: encode or decode
    choice = input("Choose an option (encode/decode): ").strip().lower()

    if choice == "encode":
        # Encode option: Get input and password
        input_text = input("Enter the text to encode: ").strip()
        encoded_text = encode(input_text, password)
        print(f"Encoded text: {encoded_text}")

    elif choice == "decode":
        # Decode option: Get the encoded text and password
        encoded_text = input("Enter the encoded text: ").strip()
        try:
            decoded_text = decode(encoded_text, password)
            print(f"Decoded text: {decoded_text}")
        except Exception as e:
            print(f"Error during decoding: {e}")

    else:
        print("Invalid option. Please choose 'encode' or 'decode'.")
        sys.exit(1)  # Exit if an invalid option is chosen

