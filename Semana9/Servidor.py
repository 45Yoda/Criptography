import asyncio
import os
import sys
import binascii
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import dh

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

    if data==b'K':
        writer.write(b'Ok')
        data = yield from reader.read(100)
        y = data
        writer.write(b'Ok')
        data = yield from reader.read(100)
        p = data
        writer.write(b'Ok')
        data = yield from reader.read(100)
        g = data

        shared_key, b_y = dhPK(y, g, p)
        print(shared_key)   

        writer.write(b_y.to_bytes(100, 'big'))

    data = yield from reader.read(100)

    while True:
        if data[:1]==b'E': break
        if not data: continue
        addr = writer.get_extra_info('peername')
        res = srvwrk.respond(data[1:], addr)
        if not res: break
        res = b'M'+res
        writer.write(res)
        yield from writer.drain()
        data = yield from reader.read(100)
    print("[%d]" % srvwrk.id)
    writer.close()


def run_server():
    loop = asyncio.get_event_loop()
    coro = asyncio.start_server(handle_echo, '127.0.0.1', 8888, loop=loop)
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
    parameters_numbers = dh.DHParameterNumbers(int.from_bytes(p, 'big'), int.from_bytes(g, 'big'))
    parameters = parameters_numbers.parameters(default_backend())

    b_private_key = parameters.generate_private_key()
    b_peer_public_key = b_private_key.public_key()

    a_public_numbers = dh.DHPublicNumbers(int.from_bytes(y, 'big'), parameters_numbers)
    a_public_key = a_public_numbers.public_key(default_backend())
    shared_key = b_private_key.exchange(a_public_key)

    b_pn = b_peer_public_key.public_numbers()        
    b_y = b_pn.y

    return shared_key, b_y

run_server()