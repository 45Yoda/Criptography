import asyncio
import os
import sys
from Crypto.Cipher import Salsa20
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding

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

	while True:
		data = yield from reader.read(100)
		if data[:1]==b'E': break
		# Receber os dados para o protocolo Diffie Hellman
		# -------------------------------------
		if data[:1]==b'y':
			y = data[1:]
			writer.write(b'OK')
			continue

		if data[:1]==b'p':
			p = data[1:]
			writer.write(b'OK')
			continue

		if data[:1]==b'g':
			g = data[1:]
			shared_key, b_y = dhPK(int.from_bytes(y, 'big'), int.from_bytes(g, 'big'), int.from_bytes(p, 'big'))
			# Envio das assinaturas do g^x e g^y
			sig_server = sig_create(b_y)
			sig_client = sig_create(y)
			writer.write(b'K' + b_y)
			writer.write(b'S' + sig_client + sig_server)
			data = yield from reader.read(513)
			# Recebe as assinaturas
			if data[:1]==b's':
				sig_client = data[1:257]
				sig_server = data[257:]
				sig_verify(sig_client, y)
				sig_verify(sig_server, b_y)
				continue
		# -------------------------------------
		if not data: continue
		addr = writer.get_extra_info('peername')
		nonce = data[1:9]
		cipher = Salsa20.new(key=shared_key, nonce=nonce)
		msg = cipher.decrypt(data[9:])
		res = srvwrk.respond(msg, addr)
		if not res: break
		res = b'M'+cipher.encrypt(res)
		writer.write(res)
		yield from writer.drain()
	print("[%d]" % srvwrk.id)
	writer.close()


def run_server():
	# Criar assiatura RSA
	sig()
	loop = asyncio.get_event_loop()
	coro = asyncio.start_server(handle_echo, '127.0.0.1', 8885, loop=loop)
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

def dhPK(y, g, p):
	parameters_numbers = dh.DHParameterNumbers(p, g)
	parameters = parameters_numbers.parameters(default_backend())

	b_private_key = parameters.generate_private_key()
	b_peer_public_key = b_private_key.public_key()

	a_public_numbers = dh.DHPublicNumbers(y, parameters_numbers)
	a_public_key = a_public_numbers.public_key(default_backend())
	shared_key = b_private_key.exchange(a_public_key)

	b_pn = b_peer_public_key.public_numbers()        
	b_y = b_pn.y

	shared_key = shared_key[:32]

	return shared_key, b_y.to_bytes(99, 'big')

def sig_verify(signature, message):
		
	with open("pubkey_Cliente.pem", "rb") as key_file:
		public_key = serialization.load_pem_public_key(
			key_file.read(),
			backend=default_backend()
		)

	public_key.verify(
		signature,
		message,
		padding.PSS(
			mgf=padding.MGF1(hashes.SHA256()),
			salt_length=padding.PSS.MAX_LENGTH
		),
		hashes.SHA256()
	)

def sig():
	private_key = rsa.generate_private_key(
		 public_exponent=65537,
		 key_size=2048,
		 backend=default_backend()
	)

	pem = private_key.private_bytes(
		encoding=serialization.Encoding.PEM,
		format=serialization.PrivateFormat.PKCS8,
		encryption_algorithm=serialization.NoEncryption()
	)
	f = open('pkey_Servidor.pem','wb')
	f.write(pem)
	f.close()

	public_key = private_key.public_key()

	pem = public_key.public_bytes(
	encoding=serialization.Encoding.PEM,
	format=serialization.PublicFormat.SubjectPublicKeyInfo
	)

	f = open('pubkey_Servidor.pem','wb')
	f.write(pem)
	f.close()

def sig_create(msg):
	with open("pkey_Servidor.pem", 'rb') as key_file:
		private_key = serialization.load_pem_private_key(
			key_file.read(),
			password=None,
			backend=default_backend()
		)

	sig_y = private_key.sign(
							msg,
							padding.PSS(
								mgf=padding.MGF1(hashes.SHA256()),
								salt_length=padding.PSS.MAX_LENGTH
									   ),
							hashes.SHA256()
							)

	return sig_y

run_server()