# Descrição
Foi implementado na comunicação Cliente/Servidor do guião Semana9 o mecanismo de assinatura digital RSA.

# Justificação das opções tomadas
Foi necessário serializar a chave privada para conseguir assinar os respetivos parâmetros do protocolo Diffie-Hellman.
Os ficheiros de chave privada e pública usadas nas assinaturas digitais são criadas no inicio da ligação entre Cliente/Servidor sendo depois reutilizados pelos outros Clientes que pretendem aceder ao Servidor (reescrevem os ficheiros com as suas próprias pares de chaves). O Servidor mantém sempre o mesmo ficheiro de chave privada e pública.

# Instruções de uso
Uso semelhante aos dos guiões anteriores.
Existe um ficheiro em jupyter com o protocolo de assinatura digital implementado.

# Dificuldades encontradas
A análise da documentação relativa ao protocolo de assinaturas RSA foi relativamente díficil. No que toca aos restantes aspectos, as dificuldades tinham sido superadas nos guiões anteriores.
