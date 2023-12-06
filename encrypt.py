from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad
import base64
import random

def generate_key_pair():
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    with open('private_key.pem', 'wb') as private_key_file:
        private_key_file.write(private_key)
    with open('public_key.pem', 'wb') as public_key_file:
        public_key_file.write(public_key)      

def encrypt_file_rsa_then_vernam_caesar_vigenere(file_path, private_key_path, output_file_path, vigenere_keyword):
    with open(private_key_path, 'rb') as key_file:
        private_key = RSA.import_key(key_file.read())

    # Generate a random symmetric key for file encryption
    symmetric_key = get_random_bytes(16)
    cipher_rsa = PKCS1_OAEP.new(private_key)
    enc_symmetric_key = cipher_rsa.encrypt(symmetric_key)

    # Use AES to encrypt the file content with the symmetric key
    cipher_aes = AES.new(symmetric_key, AES.MODE_EAX)

    with open(file_path, 'rb') as file:
        plaintext = file.read()
        ciphertext, tag = cipher_aes.encrypt_and_digest(pad(plaintext, AES.block_size))

    # Base64 encode the encrypted symmetric key and the encrypted file content
    enc_symmetric_key_b64 = base64.b64encode(enc_symmetric_key)
    ciphertext_b64 = base64.b64encode(ciphertext)
    tag_b64 = base64.b64encode(tag)

    # Write the Base64-encoded data to the output file
    with open(output_file_path, 'w') as encrypted_file:
        encrypted_file.write(enc_symmetric_key_b64.decode('utf-8') + '\n')
        encrypted_file.write(base64.b64encode(cipher_aes.nonce).decode('utf-8') + '\n')
        encrypted_file.write(tag_b64.decode('utf-8') + '\n')
        encrypted_file.write(ciphertext_b64.decode('utf-8'))

    # Read the encrypted file for further processing
    with open(output_file_path, 'r') as encrypted_file:
        encrypted_data = encrypted_file.read()

    # Vernam-Caesar-Vigenere Encryption
    vernam_caesar_vigenere_encrypted = vernam_caesar_vigenere_encrypt(encrypted_data, vigenere_keyword)

    # Overwrite the output file with the final encrypted data
    with open(output_file_path, 'w') as final_encrypted_file:
        final_encrypted_file.write(vernam_caesar_vigenere_encrypted)

def vernam_caesar_vigenere_encrypt(plaintext, vigenere_keyword):
    # Vernam Encryption
    vernam_encrypted = vernam_encrypt(plaintext)

    # Caesar Encryption
    caesar_encrypted = caesar_encrypt(vernam_encrypted, shift=3)

    # Vigenere Encryption
    vigenere_encrypted = vigenere_encrypt(caesar_encrypted, vigenere_keyword)

    return vigenere_encrypted

# Vernam Encryption
def vernam_encrypt(plaintext):
    key = ''.join([chr(random.randint(ord('A'), ord('Z'))) for _ in range(len(plaintext))])
    ciphertext = ""
    for p, k in zip(plaintext, key):
        if p.isalpha():
            base = ord('A') if p.isupper() else ord('a')
            encrypted_char = chr((ord(p) - base + ord(k) - ord('A')) % 26 + base)
            ciphertext += encrypted_char
        else:
            ciphertext += p
    return ciphertext

# Caesar Encryption
def caesar_encrypt(plaintext, shift):
    ciphertext = ""
    for char in plaintext:
        if char.isalpha():
            base = ord('A') if char.isupper() else ord('a')
            encrypted_char = chr((ord(char) - base + shift) % 26 + base)
            ciphertext += encrypted_char
        else:
            ciphertext += char
    return ciphertext

# Vigenere Encryption
def vigenere_encrypt(plaintext, keyword):
    ciphertext = ""
    keyword_repeated = (keyword * (len(plaintext) // len(keyword) + 1))[:len(plaintext)]
    for p, k in zip(plaintext, keyword_repeated):
        if p.isalpha():
            base = ord('A') if p.isupper() else ord('a')
            encrypted_char = chr((ord(p) - base + ord(k) - ord('A')) % 26 + base)
            ciphertext += encrypted_char
        else:
            ciphertext += p
    return ciphertext

# Example usage
generate_key_pair()
encrypt_file_rsa_then_vernam_caesar_vigenere('/Users/jossecleo/Documents/input.txt.rtf', 'private_key.pem', 'final_encrypted.txt', 'OAK')