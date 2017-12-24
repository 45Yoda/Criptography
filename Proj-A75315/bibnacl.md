Trabalho individual realizado por : Ricardo Certo A75315	

# Biblioteca NaCl(Networking and Cryptography library)


## O que é ? Para que serve ?

NaCl é uma biblioteca de software de alta velocidade, fácil 
de usar para comunicações na rede, assinaturas, 
criptografia, descriptografia, etc. Esta biblioteca tem como
objetivo fornecer todas as operações básicas necessárias 
para o programador construir ferramentas criptográficas de um 
nível hierárquico superior. 
Existem outras para além da NaCl, mas esta têm a vantagem de 
apresentar melhorias no que toca a segurança, velocidade e a 
sua usabilidade. 



## Características

A biblioteca NaCl apresenta as seguintes caraterísticas:
* Implementações de alta velocidade --> possui a capacidade de fornecer de velocidades de registo para cada um das suas operações criptográficas.
* Sintonização automática do CPU --> a NaCl suporta múltiplas implementações da mesma função.
* Seleção especializada de primitivas padrão --> obriga o programador a especificar todas as opções de primitivas criptográficas. Ex: "assine a mensagem com RSA de 4096 bits com SHa-256".
* Primitivas de alto nível --> a NaCl fornece uma função cripto_box simples que faz todo o processo de autenticação e criptográfico em um único passo. A função leva a chave secreta do emissor, a chave pública do recetor e uma mensagem, e produz um texto cifrado autenticado. Todos os objetos são representados no formato de fio, como sequências de bytes para transmissão; a função crypto_box gera automaticamente todas as conversões, inicializações, etc.
Outra virtude é que a NaCl não está ligada ao hash-sign-encrypt-etc e por isso apresenta soluções mais rápidas pelo facto de reutilizarem os segredos partilhados pelo protocolo de Diffie-Hellman.
* Nenhum índice de matriz depende de dados --> por questões de desempenho e segurança a cache do CPU não guarda informações secretas nos seus endereços.
* Não possui alocação de memória dinâmica --> é destinada ao uso em ambientes que não podem garantir a disponibilidade de grandes quantidades de armazenamento na stack, mas que, no
entanto dependem dos seus cálculos criptográficos para continuarem a trabalhar. 
* Sem restrições de direitos de autor --> toda a biblioteca é de domínio público.




### Funções Básicas
#### Criptografia de chave pública
 * Criptografia autenticada usando Curve25519 , Salsa20 e Poly1305.
 * Assinaturas usando Ed25519.
 * Acordo-chave usando Curve25519.

#### Criptografia de chave secreta
 * Criptografia autenticada usando Salsa20 e Poly1305.
 * Criptografia usando Salsa20 ou AES.
 * Autenticação usando HMAC-SHA-512-256.
 * Autenticação única usando Poly1305.

#### Funções de baixo nível
 * Hashing usando SHA-512 ou SHA-256.
 * Comparação de cordas. 



## Bindings para python 
PyNaCl é uma ligação em python á biblioteca libsodium, que é um "fork" da biblioteca NaCl. Essas bibliotecas têm como objetivo melhorar a usabilidade, segurança e velocidade.
Como ainda não existe a biblioteca NaCl para uso no python criou-se a biblioteca libsodium que possui uma API compatível com ela e uma API estendida para melhorar ainda mais a facilidade de uso.


## Opinião Crítica: 
Na minha opinião, o surgimento desta biblioteca criptogŕafica foi um passo importante no que toca à criptografia pois esta têm como principal objetivo fornecer todas as operações principais necessárias para construir ferramentas de nível superior. Apesar de já existirem outras bibliotecas capazes de efetuar esse tipo de operações ela torna-se mais "forte" no sentido em que a segurança, usabilidade e velocidade foram melhoradas em relação às bibliotecas que existiam anteriormente. E também por possuir todas as características mencionadas a cima, fazem dela uma biblioteca bastante confiável no mundo da criptografia.
