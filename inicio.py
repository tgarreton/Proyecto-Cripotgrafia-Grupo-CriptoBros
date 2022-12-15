from Crypto.Cipher import AES
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
import os
from Crypto import Random
from Crypto.Hash import SHA
from Crypto.Signature import PKCS1_v1_5 as Signature_pkcs1
import base64

import ghfunc as gh

def ae_encrypt(key, data):
    cipher = AES.new(key, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(data)

    return cipher.nonce + tag + ciphertext

def ae_decrypt(key, data):
    nonce = data[:AES.block_size]
    tag = data[AES.block_size:AES.block_size * 2]
    ciphertext = data[AES.block_size * 2:]

    cipher = AES.new(key, AES.MODE_EAX, nonce)
    
    return cipher.decrypt_and_verify(ciphertext, tag)

def generador_keys(bit_size,random_generator):
    keys = RSA.generate(bit_size,random_generator)
    rsa=RSA.generate(2048,random_generator)

    private_pem = rsa

    with open('ClavePrivada.pem','wb') as f:
        f.write(private_pem.exportKey())

    public_pem=rsa.publickey()
    with open('ClavePublica.pem','wb') as f:
        f.write(public_pem.exportKey())
    
    print("Se han generado las llaves")

    return (private_pem, public_pem)

def r_encrypt(pub_key, data):
    cipher = PKCS1_OAEP.new(pub_key)

    return cipher.encrypt(data)

def r_decrypt(priv_key, data):
    cipher = PKCS1_OAEP.new(priv_key)

    return cipher.decrypt(data)

key_size = 32

def h_encrypt(pub_key, data):
    session_key = os.urandom(key_size)
    enc_key = r_encrypt(pub_key, session_key)
    enc_data = ae_encrypt(session_key, data)

    return enc_key + enc_data

def h_decrypt(priv_key, data):

    key_size = priv_key.size_in_bytes()
    enc_key = data[:key_size]
    enc_data = data[key_size:]

    dec_key = r_decrypt(priv_key, enc_key)
    dec_data = ae_decrypt(dec_key, enc_data)

    return dec_data


def firmar(mensaje):
    with open("ClavePrivada.pem") as f:
        key = f.read()
        rsakey= RSA.importKey(key)
        signer = Signature_pkcs1.new(rsakey)
        
        digest = SHA.new()
        
        digest.update(mensaje)
        
        sign = signer.sign(digest)
        signature = base64.b64encode(sign)
    
    with open("firma.pem", "wb") as fp1:
        fp1.write(signature)
        fp1.close()
    print("firma creada")
    
    return signature


def verificar(mensaje, signature):
    with open("ClavePublica.pem") as f:
        key = f.read()
        rsakey= RSA.importKey(key)
        verifier = Signature_pkcs1.new(rsakey)
        
        digest = SHA.new()
        digest.update(mensaje)
    with open(signature) as f2:
        firmao = f2.read()
        is_verified  = verifier.verify(digest, base64.b64decode(firmao))
    if is_verified:
        print("Todo bien")
        return 1
    else:
        print("Error, mensaje alterado o firma incorrecta")
        return 0
        
        

def Encriptar_Mensaje(mensaje):
    with open(mensaje,"r") as f1:
        mensaje_l = f1.read()
    random_generator = Random.new().read
    (private_key, public_key)= generador_keys(2048,random_generator)
    mensaje_l=mensaje_l.encode()
    encriptar_mensaje=  h_encrypt(public_key, mensaje_l)
    with open("Mensaje_Cifrado.txt", "wb") as fp_ci:
        fp_ci.write(encriptar_mensaje)
        fp_ci.close()

def Encriptar_Mensaje_y_firmar(mensaje):
    with open(mensaje,"r") as f1:
        mensaje_l = f1.read()
    random_generator = Random.new().read
    _, public_key = generador_keys(2048,random_generator)
    mensaje_l = mensaje_l.encode()
    encriptar_mensaje =  h_encrypt(public_key, mensaje_l)
    with open("Mensaje_Cifrado.txt", "wb") as fp_ci:
        fp_ci.write(encriptar_mensaje)
        fp_ci.close()
    firmar(encriptar_mensaje)

def Desencriptar_Mensaje(private_key, mensaje_encrip):
    with open(mensaje_encrip, "rb") as f2:
        mensaje = f2.read()
        print(mensaje)
    with open(private_key) as f:
        key = f.read()
        rsakey= RSA.importKey(key)
    
    desencriptar= h_decrypt(rsakey,mensaje)
    with open("Mensaje_Descifrado.txt", "w") as fp_des:
        fp_des.write(str(desencriptar)[2:-1])
        fp_des.close()


def Desencriptar_Mensaje_y_Verificar(private_key, mensaje_encrip,firma):
    with open(mensaje_encrip, "rb") as f2:
        mensaje = f2.read()
    with open(private_key) as f:
        key = f.read()
        rsakey= RSA.importKey(key)

    val= verificar(mensaje,firma)
    if (val==1):
        desencriptar= h_decrypt(rsakey,mensaje)
        with open("Mensaje_Descifrado.txt", "w") as fp_des:
            fp_des.write(desencriptar.decode())
            fp_des.close()
        return True
    
    return False
