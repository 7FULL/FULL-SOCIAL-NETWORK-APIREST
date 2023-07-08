from flask import Flask, jsonify
from flask_cors import CORS
from main.BBDD.conecctor import BBDD
from main.blueprints.userEndpoints import user
from main.managers.mailManager import EmailManager
from main.logs.log import Logger
import json
import inspect


app = Flask(__name__)

app.register_blueprint(user)

CORS(app)

connector = BBDD()  # Conexión a la BBDD de MongoDB

emailManager = EmailManager()



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
        Logger.log_error(json_text, str(caller_args), caller_name)

    return text



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


if __name__ == '__main__':
    app.run()
