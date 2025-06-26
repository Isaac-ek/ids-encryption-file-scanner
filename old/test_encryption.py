import os
from encryption import AESGCMCipher, RSACipher

def test_aesgcm_cipher():
    print("Testing AESGCMCipher (in-memory)...")
    cipher = AESGCMCipher()
    data = b"Secret message for AES-GCM!"
    ciphertext = cipher.encrypt(data)
    plaintext = cipher.decrypt(ciphertext)
    assert plaintext == data, "AES-GCM decryption failed!"
    print("AESGCMCipher in-memory test passed.")

    # File-based test
    print("Testing AESGCMCipher (file-based)...")
    infile = "test_aesgcm_in.txt"
    outfile = "test_aesgcm_out.enc"
    decrypted_file = "test_aesgcm_decrypted.txt"
    with open(infile, 'wb') as f:
        f.write(data)
    cipher.encrypt_file(infile, outfile)
    cipher.decrypt_file(outfile, decrypted_file)
    with open(decrypted_file, 'rb') as f:
        file_plaintext = f.read()
    assert file_plaintext == data, "AES-GCM file decryption failed!"
    print("AESGCMCipher file-based test passed.")
    os.remove(infile)
    os.remove(outfile)
    os.remove(decrypted_file)

def test_rsa_cipher():
    print("Testing RSACipher (in-memory)...")
    private_key, public_key = RSACipher.generate_keypair()
    cipher_pub = RSACipher(public_key=public_key)
    cipher_priv = RSACipher(private_key=private_key)
    data = b"Secret message for RSA!"
    ciphertext = cipher_pub.encrypt(data)
    plaintext = cipher_priv.decrypt(ciphertext)
    assert plaintext == data, "RSA decryption failed!"
    print("RSACipher in-memory test passed.")

    # Test serialization
    priv_pem = cipher_priv.export_private_key()
    pub_pem = cipher_pub.export_public_key()
    loaded_priv = RSACipher.from_private_key(priv_pem)
    loaded_pub = RSACipher.from_public_key(pub_pem)
    ciphertext2 = loaded_pub.encrypt(data)
    plaintext2 = loaded_priv.decrypt(ciphertext2)
    assert plaintext2 == data, "RSA decryption after serialization failed!"
    print("RSACipher serialization test passed.")

    # File-based test
    print("Testing RSACipher (file-based)...")
    infile = "test_rsa_in.txt"
    outfile = "test_rsa_out.enc"
    decrypted_file = "test_rsa_decrypted.txt"
    with open(infile, 'wb') as f:
        f.write(data)
    loaded_pub.encrypt_file(infile, outfile)
    loaded_priv.decrypt_file(outfile, decrypted_file)
    with open(decrypted_file, 'rb') as f:
        file_plaintext = f.read()
    assert file_plaintext == data, "RSA file decryption failed!"
    print("RSACipher file-based test passed.")
    os.remove(infile)
    os.remove(outfile)
    os.remove(decrypted_file)

if __name__ == "__main__":
    test_aesgcm_cipher()
    test_rsa_cipher() 