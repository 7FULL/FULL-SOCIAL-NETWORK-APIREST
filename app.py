from flask import Flask, jsonify, request
from flask_cors import CORS
import requests

from BBDD.conecctor import BBDD

from models.user import User

app = Flask(__name__)

CORS(app)

connector = BBDD() # Conexión a la BBDD de MongoDB



#Funcion para no tener estar formateando el json todo el rato
def ret(result, status = 200, error = ""):
    return jsonify({
        "result": result,
        "status": status,
        "error": error
    })



@app.route('/')
def origin():
    return ret("Bienvenido a FULL")


@app.route('/api')
def api():
    return ret("Bienvenido a la API de FULL")


@app.route('/api/ping')
def ping():
    try:
        result = connector.ping()
        return ret(result)
    except Exception as e:
        return ret("Error al hacer ping", 500, str(e))


@app.route('/api/users')
def getUsers():
    try:
        result = connector.client.FULL.users.find()
    
        listResult = []

        for documento in result:
            documento['_id'] = str(documento['_id']) 
            listResult.append(documento)

        if len(listResult) > 0:
            return ret(listResult)
        else:
            return ret("No hay usuarios registrados", 404)
        
    except Exception as e:
        return ret("Error al obtener los usuarios", 500, str(e))


@app.route('/api/users/<string:username>')
def getUserByName(username):
    try:
        result = connector.client.FULL.users.find_one({ "username": username})

        if result:
            result['_id'] = str(result['_id'])  # Convertir el ObjectId en un string
            return ret(result)
        else:
            #Comprobamos si existe el usuario por email
            result = connector.client.FULL.users.find_one({ "email": username})
            if result:
                result['_id'] = str(result['_id'])  # Convertir el ObjectId en un string
                return ret(result)
            return ret("No existe el usuario "+username, 404)
        
    except Exception as e:
        return ret("Error al obtener el usuario "+username, 500, str(e))


@app.route('/api/users/email/<string:username>', methods=['PUT'])
def updateEmail(username):
    email = request.json['email']

    try:
        connector.client.FULL.users.update_one({"username": username}, {"$set": {"email": email}})

        return ret("Email del usuario "+username+" actualizado correctamente")
    
    except Exception as e:
        return ret("Error al actualizar el email del usuario "+username, 500, str(e))


@app.route('/api/users/phone/<string:username>', methods=['PUT'])
def updatePhone(username):
    phone = request.json['phone']

    try:
        connector.client.FULL.users.update_one({"username": username}, {"$set": {"phone": phone}})

        return ret("Teléfono del usuario "+username+" actualizado correctamente")
    
    except Exception as e:
        return ret("Error al actualizar el teléfono del usuario "+username, 500, str(e))


@app.route('/api/users/profile/<string:username>', methods=['PUT'])
def updateProfile(username):
    profile = request.json['profile']

    try:
        connector.client.FULL.users.update_one({"username": username}, {"$set": {"profile": profile}})

        return ret("FOto del usuario "+username+" actualizada correctamente")
    
    except Exception as e:
        return ret("Error al actualizar la foto del usuario "+username, 500, str(e))


@app.route('/api/users/description/<string:username>', methods=['PUT'])
def updateDescription(username):
    description = request.json['description']

    try:
        connector.client.FULL.users.update_one({"username": username}, {"$set": {"description": description}})

        return ret("Descripción del usuario "+username+" actualizada correctamente")
    
    except Exception as e:
        return ret("Error al actualizar la descripción del usuario "+username, 500, str(e))

@app.route('/api/users/<string:username>', methods=['DELETE'])
def deleteUser(username):
    try:
        connector.client.FULL.users.delete_one({"username": username})

        return ret("Usuario "+username+" eliminado correctamente")
    
    except Exception as e:
        return ret("Error al eliminar el usuario "+username, 500, str(e))


@app.route('/api/users/login', methods=['POST'])
def login():
    username = request.json['username']
    password = request.json['password']
    token = request.json['token']

    response = requests.post('https://www.google.com/recaptcha/api/siteverify', data={'secret': '6Lc099EmAAAAAAtcEPYRtw905n9YMKfm3u9OZ8YU', 'response': token})

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
    

@app.route('/api/users/register', methods=['POST'])
def register():
    username = request.json['username']
    password = request.json['password']
    email = request.json['email']
    phone = request.json['phone']

    print(username, password, email, phone)

    if getUserByName(username).json['status'] != 200:
        try:
            user = User(username, password, email, phone, connector)
            user.register()

            return ret("Usuario "+username+" registrado correctamente")
        
        except Exception as e:
            return ret("Error al registrar el usuario "+username, 500, str(e))
    else:
        return ret("Ya existe el usuario "+username, 409)


if __name__ == '__main__':
    app.run()