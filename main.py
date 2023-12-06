from Crypto.Util import number
import base64
import random

# Simple implementation of RSA key generation
def generate_rsa_key_pair():
    # Choose two large prime numbers
    p = number.getPrime(1024)
    q = number.getPrime(1024)
    
    # Compute n and phi
    n = p * q
    phi = (p - 1) * (q - 1)
    
    # Choose public key e
    e = 65537
    
    # Compute private key d
    d = number.inverse(e, phi)
    
    # Public key (n, e) and Private key (n, d)
    public_key = (n, e)
    private_key = (n, d)
    
    return private_key, public_key

# Function to save key to file
def save_key_to_file(key, filename):
    with open(filename, 'w') as file:
        file.write(','.join(map(str, key)))

# Function to save bytes key to file
def save_bytes_key_to_file(key, filename):
    with open(filename, 'wb') as file:
        file.write(key)

# Function to load key from file
def load_key_from_file(filename):
    with open(filename, 'r') as file:
        key = tuple(map(int, file.read().split(',')))
    return key

# Function to load bytes key from file
def load_bytes_key_from_file(filename):
    with open(filename, 'rb') as file:
        key = file.read()
    return key

# Simple implementation of RSA encryption
def rsa_encrypt(plaintext, public_key):
    n, e = public_key
    ciphertext = pow(plaintext, e, n)
    return ciphertext

# Simple implementation of RSA decryption
def rsa_decrypt(ciphertext, private_key):
    n, d = private_key
    plaintext = pow(ciphertext, d, n)
    return plaintext

# Function to perform Caesar cipher encryption
def caesar_cipher_encrypt(text, shift):
    result = ""
    for char in text:
        if char.isalpha():
            ascii_offset = ord('A') if char.isupper() else ord('a')
            result += chr((ord(char) - ascii_offset + shift) % 26 + ascii_offset)
        else:
            result += char
    return result

# Function to perform Caesar cipher decryption
def caesar_cipher_decrypt(text, shift):
    return caesar_cipher_encrypt(text, -shift)

# Function to encode data to Base64
def base64_encode(data):
    return base64.b64encode(data)

# Function to decode Base64 data
def base64_decode(encoded_data):
    return base64.b64decode(encoded_data)

# Function to perform Vigenère cipher encryption
def vigenere_cipher_encrypt(plaintext, key):
    result = ""
    key = key.upper()
    key_index = 0
    for char in plaintext:
        if char.isalpha():
            ascii_offset = ord('A') if char.isupper() else ord('a')
            key_char = key[key_index % len(key)]
            key_shift = ord(key_char) - ord('A')
            result += chr((ord(char) - ascii_offset + key_shift) % 26 + ascii_offset)
            key_index += 1
        else:
            result += char
    return result

# Function to perform Vigenère cipher decryption
def vigenere_cipher_decrypt(ciphertext, key):
    result = ""
    key = key.upper()
    key_index = 0
    for char in ciphertext:
        if char.isalpha():
            ascii_offset = ord('A') if char.isupper() else ord('a')
            key_char = key[key_index % len(key)]
            key_shift = ord(key_char) - ord('A')
            result += chr((ord(char) - ascii_offset - key_shift) % 26 + ascii_offset)
            key_index += 1
        else:
            result += char
    return result

# Function to generate a random key for the Vernam cipher
def generate_vernam_key(length):
    return bytes([random.randint(0, 255) for _ in range(length)])

# Function to perform Vernam cipher encryption
def vernam_cipher_encrypt(data, key):
    if len(data) != len(key):
        raise ValueError("Data and key lengths must be the same for Vernam cipher")
    encrypted_data = bytes([a ^ b for a, b in zip(data, key)])
    return encrypted_data

# Function to perform Vernam cipher decryption
def vernam_cipher_decrypt(encrypted_data, key):
    if len(encrypted_data) != len(key):
        raise ValueError("Encrypted data and key lengths must be the same for Vernam cipher")
    decrypted_data = bytes([a ^ b for a, b in zip(encrypted_data, key)])
    return decrypted_data

def encrypt_file_with_all_algorithms(public_key_file, output_file,
    caesar_shift, vigenere_key, vernam_key_file):
    # Load public key
    public_key = load_key_from_file(public_key_file)
    
    # Read the file content
    input_file = '/Users/jossecleo/Documents/input.txt.rtf'
    with open(input_file, 'rb') as file:
        plaintext = int.from_bytes(file.read(), 'big')
        print(f'Original plaintext (bytes): \n{plaintext}\n')
    
    # Encrypt with RSA
    encrypted_data_rsa = rsa_encrypt(plaintext, public_key)
    print(f'RSA-encrypted data: \n{encrypted_data_rsa}\n')
    
    # Convert the RSA-encrypted data to bytes
    encrypted_data_bytes = encrypted_data_rsa.to_bytes((encrypted_data_rsa.bit_length() + 7) // 8, 'big')
    
    # Base64 encode the RSA-encrypted data
    encrypted_data_base64 = base64.b64encode(encrypted_data_bytes).decode('utf-8')
    print(f'Base64-encoded RSA-encrypted data: \n{encrypted_data_base64}\n')
    
    # Perform Caesar cipher encryption on the Base64-encoded data
    encrypted_data_caesar = caesar_cipher_encrypt(encrypted_data_base64, caesar_shift)
    print(f'Caesar-encrypted data: \n{encrypted_data_caesar}\n')
    
    # Perform Vigenère cipher encryption on the Caesar-encrypted data
    encrypted_data_vigenere = vigenere_cipher_encrypt(encrypted_data_caesar, vigenere_key)
    print(f'Vigenère-encrypted data: \n{encrypted_data_vigenere}\n')
    
    # Generate Vernam key and save it to a file
    vernam_key = generate_vernam_key(len(encrypted_data_vigenere))
    save_bytes_key_to_file(vernam_key, vernam_key_file)
    
    # Perform Vernam cipher encryption on the Vigenère-encrypted data
    encrypted_data_vernam = vernam_cipher_encrypt(encrypted_data_vigenere.encode(), vernam_key)
    
    # Base64 encode the Vernam-encrypted data for readability
    encrypted_data_readable = base64.b64encode(encrypted_data_vernam).decode("utf8")
    print(f'Vernam-encrypted data (Base64) \n: {encrypted_data_readable}')
    
    # Save the quintuply encrypted data to a file
    with open(output_file, 'w') as file:
        file.write(encrypted_data_readable)

# Function to decrypt file using RSA, Caesar, Vigenère, and Vernam ciphers
def decrypt_file_with_all_algorithms(private_key_file, output_file,
    caesar_shift, vigenere_key, vernam_key_file):
    # Load private key
    private_key = load_key_from_file(private_key_file)
    
    # Read the file content
    input_file = '/Users/jossecleo/Documents/input.txt.rtf'
    with open(input_file, 'r') as file:
        encrypted_data_readable = file.read()
        print(f'Read Vernam-encrypted data (Base64): \n{encrypted_data_readable}\n')
    
    # Base64 decode the Vernam-encrypted data
    encrypted_data_vernam = base64.b64decode(encrypted_data_readable.encode('utf8'))
    
    # Load Vernam key from file
    vernam_key = load_bytes_key_from_file(vernam_key_file)
    
    # Perform Vernam cipher decryption on the quintuply encrypted data
    encrypted_data_vigenere = vernam_cipher_decrypt(encrypted_data_vernam, vernam_key)
    print(f'Vernam-decrypted data: {base64.b64encode(encrypted_data_vigenere).decode("utf-8")}')
    
    # Perform Vigenère cipher decryption on the Vernam-decrypted data
    encrypted_data_caesar = vigenere_cipher_decrypt(encrypted_data_vigenere.decode('utf-8'), vigenere_key)
    print(f'Vigenère-decrypted data: {encrypted_data_caesar}')
    
    # Perform Caesar cipher decryption on the Vigenère-decrypted data
    encrypted_data_base64 = caesar_cipher_decrypt(encrypted_data_caesar, caesar_shift)
    print(f'Caesar-decrypted data: {encrypted_data_base64}')
    
    # Base64 decode the RSA-encrypted data
    encrypted_data_bytes = base64.b64decode(encrypted_data_base64)
    
    # Convert the RSA-encrypted data to an integer
    encrypted_data_rsa = int.from_bytes(encrypted_data_bytes, 'big')
    print(f'Base64-decoded RSA-encrypted data: {encrypted_data_rsa}')
    
    # Decrypt with RSA
    decrypted_data = rsa_decrypt(encrypted_data_rsa, private_key)
    print(f'Decrypted data (integer): {decrypted_data}')
    
    # Save the decrypted data to a file
    with open(output_file, 'wb') as file:
        file.write(decrypted_data.to_bytes((decrypted_data.bit_length() + 7) // 8, 'big'))

def main():
    # Generate RSA key pair
    private_key, public_key = generate_rsa_key_pair()
    
    # Save keys to files
    save_key_to_file(private_key, 'private_key.txt')
    save_key_to_file(public_key, 'public_key.txt')
    
    # Set Caesar cipher shift (hardcoded value)
    caesar_shift = 3
    
    # Set Vigenère cipher key (hardcoded value)
    vigenere_key = "KEY"
    
    # Set Vernam cipher key file name
    vernam_key_file = 'vernam_key.bin'
    
    # Encrypt the file with RSA, Caesar cipher, Vigenère cipher, and Vernam cipher
    encrypt_file_with_all_algorithms('public_key.txt', 'output_encrypted.txt', caesar_shift, vigenere_key, vernam_key_file)
    print(f'File encrypted with RSA, Caesar cipher, Vigenère cipher, and Vernam cipher, and saved as output_encrypted.txt \n')
    
    # Decrypt the file with RSA, Caesar cipher, Vigenère cipher, and Vernam cipher
    decrypt_file_with_all_algorithms('private_key.txt', 'output_decrypted.txt', caesar_shift, vigenere_key, vernam_key_file)
    print(f'File decrypted with RSA, Caesar cipher, Vigenère cipher, and Vernam cipher, and saved as output_decrypted.txt \n')

if __name__ == "__main__":
    main()