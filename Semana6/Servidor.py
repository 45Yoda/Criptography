# Código baseado em https://docs.python.org/3.6/library/asyncio-stream.html#tcp-echo-client-using-streams
import asyncio

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
        addr = writer.get_extra_info('peername')
        res = srvwrk.respond(data[1:], addr)
        if not res: break
        res = b'M'+res
        cyphertext = AES.new(key,AES.MODE_CBC)
        text = cypher.decrypt(cyphertext)
        writer.write(text)
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

run_server()