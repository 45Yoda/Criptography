from OpenSSL import crypto 

passwd = "1234"

p12Ser = crypto.load_pkcs12(open("Servidor.p12",'rb').read(),passwd)
p12Cli = crypto.load_pkcs12(open("Cliente.p12",'rb').read(),passwd)

certiS = p12Ser.get_certificate()     
#print(certiS)
pkS = p12Ser.get_privatekey()
#print(pkS)      
cacertS = p12Ser.get_ca_certificates() 
#print(cacertS)


certiC = p12Cli.get_certificate()     
#print(certiC)
pkC = p12Cli.get_privatekey()
#print(pkC)      
cacertC = p12Cli.get_ca_certificates() 
#print(cacertC)




def verify():

    print("verifica inicio")
    with open('./Servidor.pem','r') as cert_file:
        cert = cert_file.read()
        

    with open('./Cliente.pem', 'r') as int_cert_file:
        int_cert = int_cert_file.read()

    with open('./CA.cer', 'r') as root_cert_file:
        root_cert = root_cert_file .read()

    trusted_certs = (int_cert, root_cert)
    verified = verify_chain_of_trust(cert, trusted_certs)

    if verified:
        print('Certificate verified')


verify()