# Código baseado em https://docs.python.org/3.6/library/asyncio-stream.html#tcp-echo-client-using-streams
import asyncio
import os
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

conn_cnt = 0


class ServerWorker(object):
    """ Classe que implementa a funcionalidade do SERVIDOR. """
    def __init__(self, cnt):
        """ Construtor da classe. """
        self.id = cnt
    def respond(self, msg, peername):
        """ Processa uma mensagem (enviada pelo CLIENTE)"""
        assert len(msg)>0, "mensagem vazia!!!"
        print('%d :%r' % (self.id,msg.decode()))
        return msg


@asyncio.coroutine
def handle_echo(reader, writer):
	global conn_cnt
	conn_cnt +=1
	srvwrk = ServerWorker(conn_cnt)
	data = yield from reader.read(100)
	while True:
		if data[:1]==b'E': break
		if not data: continue
		# Get the data from the variable to start decryption
		nonce = data[:16]
		tag = data[16:32]
		salt = data[32:48]
		ciphertext = data[48:]
		# Get key from PBKDF2
		key = passwd(salt)
		# AES cipher
		cipher = AES.new(key,AES.MODE_EAX,nonce=nonce)
		# Decryption
		plaintext = cipher.decrypt(ciphertext)
		try:
			# Verify if the message has not been corrupted
			cipher.verify(tag)
			addr = writer.get_extra_info('peername')
			res = srvwrk.respond(plaintext[1:], addr)
			if not res: break
			res = b'M'+res
			writer.write(res)
			yield from writer.drain()
			data = yield from reader.read(100)
		except ValueError:
			continue
	print("[%d]" % srvwrk.id)
	writer.close()


def run_server():
    loop = asyncio.get_event_loop()
    coro = asyncio.start_server(handle_echo, '127.0.0.1', 9999, loop=loop)
    server = loop.run_until_complete(coro)
    # Serve requests until Ctrl+C is pressed
    print('Serving on {}'.format(server.sockets[0].getsockname()))
    try:
        loop.run_forever()
    except KeyboardInterrupt:
        pass
    # Close the server
    server.close()
    loop.run_until_complete(server.wait_closed())
    loop.close()
    print('FINISHED!')

def passwd(salt):
    backend = default_backend()
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
    # Return the secrets
    return key

run_server()