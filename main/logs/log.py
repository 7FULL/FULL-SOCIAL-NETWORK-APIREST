import json
import os
import pprint
from datetime import datetime


class Logger:
    @staticmethod
    def log(response, arg, name):
        # Obtener la fecha actual
        fecha_actual = datetime.now()
        dia_actual = fecha_actual.strftime("%Y/%m/%d")

        if not os.path.exists("main/logs/" + dia_actual):
            os.makedirs("main/logs/" + dia_actual)

        # Escribir el mensaje en el archivo junto con la fecha actual
        with open("main/logs/" + dia_actual + "/Log.log", "a") as f:
            try:
                arg.locals['response'] = f"{arg.locals['response']}"

            except KeyError as e:
                pass

            try:
                arg.locals['user'] = arg.locals['user'].toJson()

            except KeyError as e:
                pass

            '''
            try:
                f.write(json.dumps(arg.locals, indent=4))
            except Exception as e:
                arg.locals = {
                    "args": str(arg.locals)
                }
            '''
                
            f.write("\n")
            f.write("\n")
            f.write(f"Date: {fecha_actual}\n")
            f.write(f"Called: {name}\n")
            f.write("Args:\n")
            f.write(json.dumps(arg.locals, default=lambda x: str(x), indent=4))
            f.write("\n")
            f.write("Response:\n")
            f.write(pprint.pformat(json.loads(response), indent=4))
            f.write("\n")
            f.write("\n")
            f.write("\n")
            f.write("<------------------------------------------------------->\n")

    @staticmethod
    def log_error(response, arg, name):
        # Obtener la fecha actual
        fecha_actual = datetime.now()
        dia_actual = fecha_actual.strftime("%Y/%m/%d")

        if not os.path.exists("main/logs/" + dia_actual):
            os.makedirs("main/logs/" + dia_actual)

        # Escribir el mensaje en el archivo junto con la fecha actual
        with open("main/logs/" + dia_actual + "/Log.log", "a") as f:
            try:
                arg.locals['response'] = f"{arg.locals['response']}"

            except KeyError as e:
                pass

            try:
                arg.locals['user'] = arg.locals['user'].toJson()

            except KeyError as e:
                pass

            f.write("\n")
            f.write("\n")
            f.write(f"Date: {fecha_actual}\n")
            f.write(f"Called: {name}\n")
            f.write("Args:\n")
            f.write(json.dumps(arg.locals, default=lambda x: str(x), indent=4))
            f.write("\n")
            f.write("Response:\n")
            f.write(pprint.pformat(json.loads(response), indent=4))
            f.write("\n")
            f.write("\n")
            f.write("\n")
            f.write("<------------------------------------------------------->\n")

