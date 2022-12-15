from github import Github

import os


def downloadFile(name):
    print(f"Descargando archivo: {name}")
    g = Github("TOKEN DE GIT")

    repo = g.get_user().get_repo("criptotransfer")

    return repo.get_contents(name).decoded_content


def uploadFile(name):
    print(f"Enviando archivo {name}")
    g = Github("TOKEN DE GIT")

    repo = g.get_user().get_repo("criptotransfer")

    archivos = []
    contenidos = repo.get_contents("")
    while contenidos:
        file_content = contenidos.pop(0)
        if file_content.type == "dir":
            contenidos.extend(repo.get_contents(file_content.path))
        else:
            file = file_content
            archivos.append(str(file).replace('ContentFile(path="','').replace('")',''))

    with open(name, 'rb') as file:
        content = file.read()

    git_file = name
    if git_file in archivos:
        contenidos = repo.get_contents(git_file)
        repo.update_file(contenidos.path, "committing files", content, contenidos.sha, branch="master")
        print(f'{git_file} ACTUALIZADO')
    else:
        repo.create_file(git_file, "committing files", content, branch="master")
        print(f'{git_file} CREADO')

def cleanup():
    archivos = ["ClavePrivada.pem", "ClavePublica.pem", "firma.pem", "Mensaje_Cifrado.txt", "Mensaje_Descifrado.txt", "descargado.txt"]
    for arc in archivos:
        try:
            os.remove(arc)
        except FileNotFoundError:
            continue
