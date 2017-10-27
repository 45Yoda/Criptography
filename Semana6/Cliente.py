# Código baseado em https://docs.python.org/3.6/library/asyncio-stream.html#tcp-echo-client-using-streams
import asyncio
import os
import sys
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

class Client:
    """ Classe que implementa a funcionalidade de um CLIENTE. """
    def __init__(self, name=b''):
        """ Construtor da classe. Recebe o nome do cliente """
        self.name = name
    def initmsg(self):
        """ Mensagem inicial """
        str = "Hello from %r!" % (self.name)
        return str.encode()
    def respond(self, msg):
        """ Processa uma mensagem (enviada pelo SERVIDOR)
        Imprime a mensagem recebida e lê do teclado a
        resposta. """
        print('Received: %r' % msg.decode())
        new = input().encode()
        return new



@asyncio.coroutine
def tcp_echo_client(loop=None):
    if loop is None:
        loop = asyncio.get_event_loop()

    reader, writer = yield from asyncio.open_connection('127.0.0.1', 9999,
                                                        loop=loop)

    data = b'S'
    client = Client("Cliente 1")
    msg = client.initmsg()
    while len(data)>0:
        if msg:
            msg = b'M' + msg
            # Key created with PBKDF2
            key, salt = passwd()
            # Encryption with AES block cipher
            cipher = AES.new(key, AES.MODE_EAX)
            nonce = cipher.nonce
            # Encrypt and creates a tag for later verify if the message has not been corrupted
            ciphertext, tag = cipher.encrypt_and_digest(msg)
            # Nonce, tag and salt saved along with the encrypted message to send to the server
            text = nonce + tag + salt + ciphertext
            writer.write(text)
            # End of encryption
            if msg[:1] == b'E': break
            data = yield from reader.read(100)
            if len(data)>0 :
                msg = client.respond(data[1:])
            else:
                break
        else:
            break
    writer.write(b'E')
    print('Socket closed!')
    writer.close()


def run_client():
    loop = asyncio.get_event_loop()
    loop.run_until_complete(tcp_echo_client())

def passwd():
    backend = default_backend()
    salt = os.urandom(16)
    # PBKDF2 derivation function
    kdf = PBKDF2HMAC(
    algorithm=hashes.SHA256(),
    length=32,
    salt=salt,
    iterations=100000,
    backend=backend
    )
    # pass-phrase
    password = b"Some password"
    # Encrypt password with PBKDF2
    key = kdf.derive(password)
    # Return key and salt
    return key, salt


run_client()