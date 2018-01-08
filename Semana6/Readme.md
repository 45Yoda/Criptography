# Descrição
Foi implementado uma função passwd() contendo o código necessário para criar uma chave aleatória baseada numa password. Para isto, foi usado o mecanismo PBKDF2-HMAC.
De seguida a mensagem é cifrada usando o método criptográfico AES block cipher com o modo EAX.

# Justificação das opções tomadas
Foi usado o modo EAX pois, apesar de ser um pouco mais lento que os demais, garante uma segurança com qualidades adequadas.
Foi utilizado o mecanismo PBKDF2-HMAC pois foi já usado nos guiões anteriores.

# Instruções de uso
Para se executar este guião é necessário ter o python3 instalado.
Comandos:
- python3 Servidor.py - Executa o servidor
- python3 Cliente.py - Executa um cliente

# Dificuldades encontradas
Foi necessário perceber a forma como o servidor e o cliente estavam implementados para começar o processo de encriptação e desincriptação das mensagens.
Quanto ás técnicas usadas, devido à documentação providênciada pelo pycryptodome e o cryptography, não foram encontradas muitas dificuldades que não se conseguisse superar.


