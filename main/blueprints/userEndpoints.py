from flask import Blueprint, request, jsonify, request, send_file
import os
from main.BBDD.conecctor import BBDD
from main.managers.mailManager import EmailManager
import requests
from main.models.user import User
import hashlib
import inspect
import json
from main.logs.log import Logger
import random
import string


connector = BBDD()
emailManager = EmailManager()


user = Blueprint('user', __name__)


# Funcion para no tener estar formateando el json tod el rato
def ret(result, status=200, error=""):
    text = jsonify({
        "result": result,
        "status": status,
        "error": error
    })

    log = {
        "result": result,
        "status": status,
        "error": error
    }

    # Obtenemos la informacion de la funcion que ha llamado a log
    caller_frame = inspect.currentframe().f_back
    caller_name = caller_frame.f_code.co_name
    caller_args = inspect.getargvalues(caller_frame)

    json_text = json.dumps(log)

    if error == "":
        Logger.log(json_text, caller_args, caller_name)
    else:
        Logger.log_error(json_text, caller_args, caller_name)

    return text


def hash_password(password):
    # Crear un objeto hash utilizando el algoritmo SHA-256
    hasher = hashlib.sha256()

    # Convertir la contraseña en bytes antes de hashearla
    password_bytes = password.encode('utf-8')

    # Hashear la contraseña
    hasher.update(password_bytes)

    # Obtener el hash resultante en formato hexadecimal
    hashed_password = hasher.hexdigest()

    return hashed_password


@user.route('/api/users')
def getUsers():
    try:
        result = connector.client.FULL.users.find()

        listResult = []

        for documento in result:
            documento['password'] = "SSSSSHHHH SECRET"

            documento['_id'] = str(documento['_id'])
            listResult.append(documento)

        if len(listResult) > 0:
            return ret(listResult)
        else:
            return ret("No hay usuarios registrados", 404)

    except Exception as e:
        return ret("Error al obtener los usuarios", 500, str(e))

@user.route('/api/users/<string:username>')
def getUserByNameOrEmail(username, email=False):
    try:
        result = connector.client.FULL.users.find_one({"username": username})

        if result:
            result['password'] = "SSSSSHHHH SECRET"

            result['_id'] = str(result['_id'])  # Convertir el ObjectId en un string
            return ret(result)
        else:
            # Comprobamos si existe el usuario por email
            if email:
                username = email

            result = connector.client.FULL.users.find_one({"email": username})

            if result:
                result['password'] = "SSSSSHHHH SECRET"

                result['_id'] = str(result['_id'])  # Convertir el ObjectId en un string
                return ret(result)
            return ret("No existe el usuario " + username, 404)

    except Exception as e:
        return ret("Error al obtener el usuario " + username, 500, str(e))

@user.route('/api/users/email/<string:username>', methods=['PUT'])
def updateEmail(username):
    email = request.json['newMail']
    password = request.json['password']

    try:
        result = connector.client.FULL.users.find_one({"username": username})

        if result:
            result['_id'] = str(result['_id'])

            if result['password'] == hash_password(password):

                oldEmail = connector.client.FULL.users.find_one({"username": username})['email']

                connector.client.FULL.users.update_one({"username": username}, {"$set": {"email": email}})

                emailManager.sendEmailChanged(oldEmail, username)

                return ret("Email del usuario " + username + " actualizado correctamente")
            else:
                return ret("La contraseña no coincide", 400)
        else:
            return ret("No existe el usuario " + username, 404)

    except Exception as e:
        return ret("Error al actualizar el email del usuario " + username, 500, str(e))

@user.route('/api/users/phone/<string:username>', methods=['PUT'])
def updatePhone(username):
    phone = request.json['newPhone']
    password = request.json['password']

    try:
        result = connector.client.FULL.users.find_one({"username": username})

        if result:
            result['_id'] = str(result['_id'])

            if result['password'] == hash_password(password):

                connector.client.FULL.users.update_one({"username": username}, {"$set": {"phone": phone}})

                emailManager.sendPasswordChanged(result['email'], username)

                return ret("Teléfono del usuario " + username + " actualizado correctamente")
            else:
                return ret("La contraseña no coincide", 400)
        else:
            return ret("No existe el usuario " + username, 404)

    except Exception as e:
        return ret("Error al actualizar el teléfono del usuario " + username, 500, str(e))

@user.route('/api/users/profile/<string:username>', methods=['PUT'])
def updateProfile(username):
    if 'profile' in request.files:
        try:
            os.remove("users/" + username)  # Eliminar el archivo antiguo

            file = request.files['profile']
            filename = username

            if filename == '':  # Nombre de archivo vacio
                return ret("El nombre del archivo no puede estar vacio", 400)

            allowed_extensions = {'png', 'jpg', 'jpeg'}
            extension = filename.rsplit('.', 1)[1].lower()  # Obtener la extension del archivo

            if extension not in allowed_extensions:
                return ret("La extension " + extension + " no esta permitida", 400)

            max_size = 1024 * 1024 * 5  # 5MB
            size = len(file.read())

            file.seek(0)  # Volver al inicio del archivo

            if size > max_size:
                return ret("El tamaño maximo permitido es de 5MB", 413)

            file.save("users/" + filename)  # Guardar el archivo en la carpeta users

            try:
                connector.client.FULL.users.update_one({"username": username}, {"$set": {"profile": username+"."+extension}})

                return ret("Foto del usuario " + username + " actualizada correctamente")

            except Exception as e:
                return ret("Error al actualizar la foto del usuario " + username, 500, str(e))

        except Exception as e:
            return ret("Error al obtener el usuario " + username, 500, str(e))

    else:
        return ret("No se ha enviado ningun archivo", 404)

@user.route('/api/users/password/<string:username>', methods=['PUT'])
def updatePassword(username):
    oldPassword = request.json['oldPassword']
    newPassword = request.json['newPassword']

    try:
        result = connector.client.FULL.users.find_one({"username": username})

        if result:
            result['_id'] = str(result['_id'])
            if result['password'] == hash_password(oldPassword):
                connector.client.FULL.users.update_one({"username": username},
                                                       {"$set": {"password": hash_password(newPassword)}})

                emailManager.sendPasswordChanged(result['email'], result['username'])

                return ret("Contraseña del usuario " + username + " actualizada correctamente")
            else:
                return ret("La contraseña antigua no coincide", 400)
        else:
            return ret("No existe el usuario " + username, 404)

    except Exception as e:
        return ret("Error al actualizar la contraseña del usuario " + username, 500, str(e))

@user.route('/api/users/profile/<string:username>', methods=['GET'])
def getProfile(username):
    directory = "users/"
    filename = username

    try:
        if os.path.exists(directory + filename):
            return send_file(directory + filename)
        else:
            return ret("No existe el perfil del usuario " + username, 404)

    except Exception as e:
        return ret("Error al obtener la foto de perfil del usuario " + username, 500, str(e))

@user.route('/api/users/description/<string:username>', methods=['PUT'])
def updateDescription(username):
    description = request.json['description']

    try:
        connector.client.FULL.users.update_one({"username": username}, {"$set": {"description": description}})

        return ret("Descripción del usuario " + username + " actualizada correctamente")

    except Exception as e:
        return ret("Error al actualizar la descripción del usuario " + username, 500, str(e))

@user.route('/api/users/<string:username>', methods=['DELETE'])
def deleteUser(username):
    try:
        password = request.json['password']

        password = hash_password(password)

        result = connector.client.FULL.users.find_one({"username": username})

        if result:
            result['_id'] = str(result['_id'])

            if result['password'] == password:

                connector.client.FULL.users.delete_one({"username": username})

                if result['profile']:
                    os.remove("users/" + result['profile'])  # Eliminar el archivo de la foto de perfil

                return ret("Usuario " + username + " eliminado correctamente")

            else:
                return ret("La contraseña no coincide", 401)

        else:
            return ret("No existe el usuario " + username, 404)

    except Exception as e:
        return ret("Error al eliminar el usuario " + username, 500, str(e))

@user.route('/api/users/login', methods=['POST'])
def login():
    username = request.json['username']
    password = request.json['password']

    password = hash_password(password)

    token = request.json['token']

    response = requests.post('https://www.google.com/recaptcha/api/siteverify',
                             data={'secret': '6Lc099EmAAAAAAtcEPYRtw905n9YMKfm3u9OZ8YU', 'response': token})

    if response.json()['success']:
        try:
            result = User.login(username, connector)

            if result:
                result['_id'] = str(result['_id'])
                if result["password"] == password:
                    return ret(True)
                else:
                    # Aqui podriamos devolver un contrasñea incorrecta pero lo he hecho asi
                    # para que no se sepa si el usuario existe o no
                    return ret(False, 401, "Usuario o contraseña incorrectos")
            else:
                return ret(False, 401, "Usuario o contraseña incorrectos")

        except Exception as e:
            return ret("Error al hacer login", 500, str(e))
    else:
        return ret(response.json(), 498, "Creemos que eres un robot")

@user.route('/api/users/register', methods=['POST'])
def register():
    username = request.json['username']
    password = request.json['password']
    email = request.json['email']
    phone = request.json['phone']

    caracteres = string.ascii_letters + string.digits
    caracteres = caracteres.replace('"', '').replace("'", '').replace("`", '')

    token = ''.join(random.choice(caracteres) for _ in range(8))

    password = hash_password(password)

    if getUserByNameOrEmail(username, email).json['status'] != 200:
        try:
            user = User(username, password, email, phone, connector)
            user.register(token)

            emailManager.sendWelcomeEmail(email, username)

            return ret("Usuario " + username + " registrado correctamente")

        except Exception as e:
            return ret("Error al registrar el usuario " + username, 500, str(e))
    else:
        return ret("Ya existe el usuario " + username, 409)

@user.route('/api/users/registerToken/<string:username>', methods=['GET'])
def registerToken(username):
    caracteres = string.ascii_letters + string.digits
    caracteres = caracteres.replace('"', '').replace("'", '').replace("`", '')

    token = ''.join(random.choice(caracteres) for _ in range(8))

    try:
        connector.client.FULL.users.update_one({"username": username}, {"$set": {"token": token}})

        result = connector.client.FULL.users.find_one({"username": username})

        emailManager.sendTokenSended(result['email'], result['username'], token)

        return ret("Token del usuario " + username + " actualizado correctamente")
    
    except Exception as e:
        return ret("Error al actualizar la descripción del usuario " + username, 500, str(e))

@user.route('/api/users/checkToken/<string:username>', methods=['POST'])
def checkToken(username):
    token = request.json['token']  
        
    result = connector.client.FULL.users.find_one({
        "username": username
    })  

    if result:
        result['_id'] = str(result['_id'])
        if result['token'] == token:
            connector.client.FULL.users.update_one({"username": username}, {"$set": {"token": "", "emailVerified": True}})
            return ret(True)
        else:
            return ret(False, 401, "Token incorrecto")    

@user.route('/api/users/getProfileByStreamName/<string:streamName>', methods=['GET'])
def getProfileByStreamName(streamName):
    directory = "users/"
    filename = ""

    try:
        result = connector.client.FULL.streams.find_one({"name": streamName})

        if result:
            filename = result['username']
        else:
            return ret("No existe el stream " + streamName, 404)

    except Exception as e:
        return ret("Error al obtener la informacion del stream " + streamName, 500, str(e))

    try:
        allowed_extensions = {'png', 'jpg', 'jpeg'}
        for extension in allowed_extensions:
            if os.path.exists(directory + filename + "." + extension):
                return send_file(directory + filename + "." + extension)
        else:
            return ret("No existe el perfil del usuario " + filename, 404)

    except Exception as e:
        return ret("Error al obtener la foto de perfil del usuario " + filename, 500, str(e))
