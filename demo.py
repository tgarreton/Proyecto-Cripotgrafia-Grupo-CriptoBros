from inicio import *
try:
    gh.cleanup()
    input("1)")
    Encriptar_Mensaje_y_firmar("notas.txt")
    input("2)")
    gh.uploadFile("Mensaje_Cifrado.txt")
    input("3)")
    cifrado = gh.downloadFile("Mensaje_Cifrado.txt")
    input("4)")
    open("descargado.txt", "wb").write(cifrado)
    print("Archivo escrito")
    input("5)")
    while True:
            Desencriptar_Mensaje_y_Verificar("ClavePrivada.pem","descargado.txt","firma.pem")
            input("REPITIENDO...")
except KeyboardInterrupt:
    pass
