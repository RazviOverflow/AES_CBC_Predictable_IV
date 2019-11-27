# 247CTF Predictable Vectors

How to break AES.CBC mode when the server is running the following code:

```python
from flask import Flask, session, request
from Crypto import Random
from Crypto.Cipher import AES
from secret import flag, aes_key, secret_key

app = Flask(__name__)
app.secret_key = secret_key
app.config['DEBUG'] = False

class AESCipher():
    def __init__(self):
        self.pad = lambda s: s + (AES.block_size - len(s) % AES.block_size) * chr(AES.block_size - len(s) % AES.block_size)

    def encrypt(self, raw):
        cipher = AES.new(aes_key, AES.MODE_CBC, session.get("IV"))
        encrypted = cipher.encrypt(self.pad(raw + flag))
        session["IV"] = encrypted[-AES.block_size:]
        return encrypted.encode("hex")

@app.before_request
def before_request():
    if session.get("IV") is None:
        session["IV"] = Random.new().read(AES.block_size)

@app.route("/")
def main():
    return "

%s

" % open(__file__).read()

@app.route("/flag_format")
def flag_format():
    return """The flag format for this challenge is non-standard.

        The flag to obtain for this challenge (stored in the flag variable) is 32-HEX only.

        Once you obtain this flag, submit your solution in the regular 247CTF{32-HEX} format."""

@app.route("/encrypt")
def encrypt():
    try:
        return AESCipher().encrypt(request.args.get('plaintext').decode('hex'))
    except:
        return "Something went wrong!"

if __name__ == "__main__":
    app.run()

```
