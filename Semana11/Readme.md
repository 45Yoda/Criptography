# Descrição
É utilizado o OpenSSL para a validação de cadeias de certificados. Neste guião foi implementado um código em python utilizando a biblioteca pyOpenSSL para esse fim.

# Justificação das opções tomadas
Inicialmente são criados ficheiros PEM para ser possível a verificação dos certificados.

# Instruções de uso
São necessários os ficheiros que se encontram na pasta para poder executar o ficheiro jupyter.
É necessário ter o OpenSSL instalado.

# Dificultades encontradas
Não conseguimos implementar uma forma, utilizando a biblioteca pyOpenSSL, para verificar os certificados, usando-se assim código python que nos permitiu a utilização do OpenSSL tipicamente utilizada pelo terminal do linux.
Inicialmente o nosso objetivo era de implementar totalmente com a biblioteca pyOpenSSL mas na verificação deparávamo-nos com um erro de confiança depositada nos certificados (non-trusted certificates).
