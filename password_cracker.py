import hashlib

def crack_sha1_hash(hash, use_salts = False):
    salts = None
    # opening salts file only when needed
    if use_salts:
        salts = open("known-salts.txt", 'r')
    with open("top-10000-passwords.txt", 'r') as passwords:
        # itering over each password in our passfile until we hit a match
        while True:
            passw = passwords.readline()
            if not passw:
                break
            passw = passw.rstrip()
            if use_salts:
                enc_pass = passw.encode('utf-8')
                # We don't need to reopen file here, we just seek to start of file
                salts.seek(0)
                while True:
                    salt = salts.readline()
                    if not salt:
                        break
                    salt = salt.rstrip().encode('utf-8')
                    # Here we either prepend the salt or append it
                    for i in range(0, 2):
                        sha1 = hashlib.sha1()
                        if i == 0:
                            sha1.update(salt)
                        sha1.update(enc_pass)
                        if i == 1:
                            sha1.update(salt)
                        if sha1.hexdigest() == hash:
                            if salts:
                                salts.close()
                            return passw
            else:
                sha1 = hashlib.sha1()
                sha1.update(passw.encode('utf-8'))
                if sha1.hexdigest() == hash:
                    return passw
    if salts:
        salts.close()
    return "PASSWORD NOT IN DATABASE"
