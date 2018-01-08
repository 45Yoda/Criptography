# Descrição
Foi implementado, na comunicação entre Servidor/Cliente, o protocolo Diffie-Hellman onde foram distribuídas as informações das chaves necessárias para a criação de uma chave em comum (shared key).

# Justificação das opções tomadas
Foram enviados em separado os números dos parâmetros e da chave pública necessários para a recriação das chaves públicas usadas tanto pelo Servidor como pelo Cliente pois não era possível enviar essa chave pública já criada.
Foi usado a cifra Salsa20 porque foi usada em guiões anteriores e não tinha impacto no objetivo do guião.

# Instruções de uso
É usada a comunicação Servido/Cliente da mesma forma do que em guiões anteriores.
Existe uma versão do protocolo em jupyter no qual é só implementada esse protocolo.

# Dificuldades encontradas
Foram encontradas dificuldades no envio da informação relativa à chave pública tanto do Cliente como do Servidor como também em como este protocolo era implementado em python pois a documentação não disponibiliza muita informação relevante.
