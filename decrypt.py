from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Util.Padding import unpad
import base64

def decrypt_file_rsa_then_vernam(private_key_path, encrypted_file_path, output_file_path):
    try:
        with open(private_key_path, 'rb') as key_file:
            private_key = RSA.import_key(key_file.read())

        # Read the encrypted file
        with open(encrypted_file_path, 'r') as encrypted_file:
            enc_symmetric_key_b64 = encrypted_file.readline().strip()
            nonce_b64 = encrypted_file.readline().strip()
            tag_b64 = encrypted_file.readline().strip()
            ciphertext_b64 = encrypted_file.read()

        # Base64 decode the encrypted symmetric key and the encrypted file content
        enc_symmetric_key = base64.b64decode(enc_symmetric_key_b64)
        nonce = base64.b64decode(nonce_b64)
        tag = base64.b64decode(tag_b64)
        ciphertext = base64.b64decode(ciphertext_b64)

        # Decrypt the symmetric key using RSA
        cipher_rsa = PKCS1_OAEP.new(private_key)
        symmetric_key = cipher_rsa.decrypt(enc_symmetric_key)

        # Use AES to decrypt the file content with the symmetric key
        cipher_aes = AES.new(symmetric_key, AES.MODE_EAX, nonce=nonce)
        decrypted_data = unpad(cipher_aes.decrypt_and_verify(ciphertext, tag), AES.block_size)

        # Write the decrypted data to the output file
        with open(output_file_path, 'wb') as decrypted_file:
            decrypted_file.write(decrypted_data)

        print("Decryption successful.")
    except Exception as e:
        print(f"Decryption failed. Error: {e}")

# Example usage
decrypt_file_rsa_then_vernam('private_key.pem', 'final_encrypted.txt', 'decrypted_output.txt')