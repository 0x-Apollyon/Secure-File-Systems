import secrets
import os
from argon2 import PasswordHasher
import hashlib
from Crypto.Cipher import AES
import json
import gc

def decrypt_text(text , key , nonce):
    cipher = AES.new(key, AES.MODE_EAX , nonce=nonce)
    text = cipher.decrypt(text)
    return text

def encrypt_text(text , key):
    cipher = AES.new(key, AES.MODE_EAX)
    nonce = cipher.nonce
    file_text = cipher.encrypt(text.encode())
    return (file_text , nonce)

def generate_key_two(password , salt=None , salt_two=None , salt_three = None):

    ph = PasswordHasher(time_cost=16 , hash_len=64)
    hash = ph.hash(password , salt=salt)


    h = hashlib.new('sha3_256')
    h.update(salt_two)
    h.update(hash.encode())
    h.update(salt_three)
    
    main_key = h.digest()

    return main_key

def generate_key(password):
    salt = secrets.token_bytes(128)
    ph = PasswordHasher(time_cost=16 , hash_len=64)
    hash = ph.hash(password , salt=salt)

    salt_two = secrets.token_bytes(128)
    salt_three = secrets.token_bytes(128)

    h = hashlib.new('sha3_256')
    h.update(salt_two)
    h.update(hash.encode())
    h.update(salt_three)
    
    main_key = h.digest()

    return (main_key , salt , salt_two , salt_three)


class secureFile:
    def __init__(self , file_path , password , mode , file_content=None):     
        print(file_path , password , mode)   
        mode = mode.lower()    
        if os.path.isdir(file_path):
            raise ValueError("The filepath is a directory not a file") 
        else:
            self.file_path = file_path

        self.file_content = file_content
        self.password = password
        if mode in ["wb" , "rb" , "ab" , "w" , "r" , "a"]:
            self.mode = mode
        else:
            raise ValueError("Not a valid file mode") 

    def write(self , file_content = None):
        if "w" not in self.mode and "a" not in self.mode:
            raise ValueError("File is currently opened in read mode") 
        else:
            if "b" in self.mode:
                if file_content:
                    f = open(self.file_path , self.mode)
                    encryption_key , salt_1 , salt_2 , salt_3 = generate_key(self.password)
                    encrypted_text , nonce = encrypt_text(file_content , encryption_key)
                    encrypted_text = encrypted_text.decode("latin-1")
                    file_content_to_write = {
                        "salt1":salt_1.decode("latin-1"),
                        "salt2":salt_2.decode("latin-1"),
                        "salt3":salt_3.decode("latin-1"),
                        "nonce":nonce.decode("latin-1"),
                        "content":encrypted_text
                    }
                    file_content_to_write = json.dumps(file_content_to_write).encode()
                    f.write(file_content_to_write)
                    f.close()

                    del f 
                    del file_content_to_write
                    del salt_1
                    del salt_2
                    del salt_3
                    del encryption_key
                    del encrypted_text
                    del nonce
                    gc.collect()
                else:
                    raise ValueError("File content empty")
            else:
                if file_content:
                    f = open(self.file_path , self.mode)
                    encryption_key , salt_1 , salt_2 , salt_3 = generate_key(self.password)
                    encrypted_text , nonce = encrypt_text(file_content , encryption_key)
                    encrypted_text = encrypted_text.decode("latin-1")
                    file_content_to_write = {
                        "salt1":salt_1.decode("latin-1"),
                        "salt2":salt_2.decode("latin-1"),
                        "salt3":salt_3.decode("latin-1"),
                        "nonce":nonce.decode("latin-1"),
                        "content":encrypted_text
                    }

                    file_content_to_write = json.dumps(file_content_to_write)
                    f.write(file_content_to_write)
                    f.close()

                    del f 
                    del file_content_to_write
                    del salt_1
                    del salt_2
                    del salt_3
                    del encryption_key
                    del encrypted_text
                    del nonce
                    gc.collect()
                else:
                    raise ValueError("File content empty")     

    def read(self):      
        if "r" not in self.mode:
            raise ValueError("File is not opened in read mode") 
        else:
            if "b" in self.mode:
                f = open(self.file_path , "r")
                file_content = f.read()
                f.close()

                file_content = json.loads(file_content)

                salt_1 = file_content["salt1"].encode("latin-1")
                salt_2 = file_content["salt2"].encode("latin-1")
                salt_3 = file_content["salt3"].encode("latin-1")
                nonce = file_content["nonce"].encode("latin-1")
                content = file_content["content"].encode("latin-1")

                encryption_key = generate_key_two(self.password , salt_1 , salt_2 , salt_3)

                decrypted_text = decrypt_text(content , encryption_key , nonce)
                self.file_content = decrypted_text

                del f 
                del salt_1
                del salt_2
                del salt_3
                del encryption_key
                del nonce
                del file_content
                del content
                gc.collect()

                return decrypted_text

            else:
                
                f = open(self.file_path , "r")
                file_content = f.read()
                f.close()

                file_content = json.loads(file_content)

                salt_1 = file_content["salt1"].encode("latin-1")
                salt_2 = file_content["salt2"].encode("latin-1")
                salt_3 = file_content["salt3"].encode("latin-1")
                nonce = file_content["nonce"].encode("latin-1")
                content = file_content["content"].encode("latin-1")

                encryption_key = generate_key_two(self.password , salt_1 , salt_2 , salt_3)

                decrypted_text = decrypt_text(content , encryption_key , nonce)
                self.file_content = decrypted_text.decode("latin-1")

                del f 
                del salt_1
                del salt_2
                del salt_3
                del encryption_key
                del nonce
                del file_content
                del content
                gc.collect()

                return decrypted_text.decode("latin-1")