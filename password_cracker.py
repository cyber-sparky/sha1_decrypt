import hashlib

def crack_sha1_hash(hash, use_salts=False):
    with open("top-10000-passwords.txt", 'r', encoding='utf-8') as file:
        for password in file.readlines():
            password = password.strip()
            if use_salts:
                # Try different salts with the password
                salts = open("known-salts.txt", "r", encoding='utf-8').readlines()
                for salt in salts:
                    salt = salt.strip()
                    salted_password = salt + password
                    hashed_password = hashlib.sha1(salted_password.encode('utf-8')).hexdigest()
                    if hash == hashed_password:
                        return salted_password
            else:
                # Just hash the password without any salt
                hashed_password = hashlib.sha1(password.encode('utf-8')).hexdigest()
                if hash == hashed_password:
                    return password
        return "PASSWORD NOT IN DATABASE"

hashed_password = input("Enter the SHA-1 hash to crack: ")
result = crack_sha1_hash(hashed_password)
print(f"Cracked Password: {result}")
