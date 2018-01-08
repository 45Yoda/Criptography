# Descrição
Geração dos Certificados para a aplicação do Cliente/Servidor. Para o processo de criação do certificado vamos precisar de gerar um par de chaves pública/privada, e emitir uma requisão para criar o certificado e por fim criamos o certificado.


# Justificação das opções tomadas
Para gerarmos os certificados decidimos usar o openssl, mais especificamente a biblioteca pyOpenSSL. Decidimos também que o certificado criado vai possuir ter validade de 1 ano.


# Instruções de uso
Abrir o ficheiro Semana13 no jupyter notebook e executar as funções. 


# Dificuldades encontradas
Dificuldade em compreender a biblioteca pyOpenSSL responsável pela criação dos certificados.