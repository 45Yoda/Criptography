import asyncio
import os
import sys
from Crypto.Cipher import Salsa20
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding

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

	reader, writer = yield from asyncio.open_connection('127.0.0.1', 8885,
														loop=loop)
	# Envio e criação do protocolo de chaves Diffie Hellman e assinatura RSA
	# ---------------------------------
	a_pr, msg_pk, private_key = dhPK()

	writer.write(b'y' + msg_pk[0])
	data = yield from reader.read(100)
	writer.write(b'p' + msg_pk[1])
	data = yield from reader.read(100)
	writer.write(b'g' + msg_pk[2])
	data = yield from reader.read(100)

	if data[:1]==b'K':
		server_y= data[1:]
		# Recebe assinaturas
		data = yield from reader.read(513)
		if data[:1]==b'S':
			sig_client = data[1:257]
			sig_server = data[257:]
			sig_verify(sig_server, server_y)
			sig_verify(sig_client, msg_pk[0])

	# Shared Key e envio de assinaturas
	shared_key = dhShared(a_pr, int.from_bytes(server_y, 'big'), private_key)
	sig_client = sig_create(msg_pk[0])
	sig_server = sig_create(server_y)

	writer.write(b's' + sig_client + sig_server)
	# ---------------------------------
	data = b'S'
	client = Client("Cliente 1")
	msg = client.initmsg()
	while len(data)>0:
		if msg:
			cipher = Salsa20.new(key=shared_key)
			msg = cipher.nonce + cipher.encrypt(msg)
			msg = b'M' + msg
			writer.write(msg)
			if msg[:1] == b'E': break
			data = yield from reader.read(100)
			if len(data)>0 :
				msg = client.respond(cipher.decrypt(data[1:]))
			else:
				break
		else:
			break
	writer.write(b'E')
	print('Socket closed!')
	writer.close()


def run_client():
	# Criar assiatura RSA
	sig()
	loop = asyncio.get_event_loop()
	loop.run_until_complete(tcp_echo_client())

def dhPK():
	parameters = dh.generate_parameters(generator=2, key_size=512, backend=default_backend())

	a_private_key = parameters.generate_private_key()
	a_peer_public_key = a_private_key.public_key()

	a_pn = a_peer_public_key.public_numbers()
	a_pr = parameters.parameter_numbers()
	a_y = a_pn.y
	a_p = a_pr.p
	a_g = a_pr.g

	num = [a_y.to_bytes(99, 'big'), a_p.to_bytes(99, 'big'), a_g.to_bytes(99, 'big')]

	return a_pr, num, a_private_key

def dhShared(a_pr, servidor_public_key, private_key):
	b_public_numbers = dh.DHPublicNumbers(servidor_public_key, a_pr)
	b_public_key = b_public_numbers.public_key(default_backend())

	shared_key = private_key.exchange(b_public_key)
	shared_key = shared_key[:32]

	return shared_key

def sig_verify(signature, message):
		
	with open("pubkey_Servidor.pem", "rb") as key_file:
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
	f = open('pkey_Cliente.pem','wb')
	f.write(pem)
	f.close()

	public_key = private_key.public_key()

	pem = public_key.public_bytes(
	encoding=serialization.Encoding.PEM,
	format=serialization.PublicFormat.SubjectPublicKeyInfo
	)

	f = open('pubkey_Cliente.pem','wb')
	f.write(pem)
	f.close()

def sig_create(msg):
	with open("pkey_Cliente.pem", 'rb') as key_file:
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


run_client()