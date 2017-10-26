# Código baseado em https://docs.python.org/3.6/library/asyncio-stream.html#tcp-echo-client-using-streams
import asyncio

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

    reader, writer = yield from asyncio.open_connection('127.0.0.1', 8888,
                                                        loop=loop)

    data = b'S'
    client = Client("Cliente 1")
    msg = client.initmsg()
    while len(data)>0:
        if msg:
            msg = b'M' + msg
            writer.write(msg)
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


run_client()