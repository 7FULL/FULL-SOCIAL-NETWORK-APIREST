from mailjet_rest import Client


class EmailManager:

    def __init__(self):
        api_key = '6c15b25b5e8166204d2c388114d68101'
        api_secret = '3baef8ff9b8cd415598284268992c1b3'
        self.mailjet = Client(auth=(api_key, api_secret), version='v3.1')

    def sendEmail(self, email, name, subject, text):
        data = {
            'Messages': [
                {
                    "From": {
                        "Email": "phermidagomez@gmail.com",
                        "Name": "FULL"
                    },
                    "To": [
                        {
                            "Email": email,
                            "Name": name
                        }
                    ],
                    "Subject": subject,
                    "HTMLPart": text
                }
            ]
        }
        result = self.mailjet.send.create(data=data)

        return result.status_code

    def sendWelcomeEmail(self, email, name):
        data = {
            'Messages': [
                {
                    "From": {
                        "Email": "phermidagomez@gmail.com",
                        "Name": "FULL"
                    },
                    "To": [
                        {
                            "Email": email,
                            "Name": name
                        }
                    ],
                    "Subject": "Bienvenido a FULL",
                    "HTMLPart": '''
          <!DOCTYPE html>
          <html>
          <head>
            <meta charset="UTF-8">
            <title>Verificación de correo electrónico</title>
            <style>
              /* Estilos generales */
              body {
                font-family: Arial, sans-serif;
                background-color: #f6f6f6;
                margin: 0;
                padding: 0;
              }

              /* Contenedor principal */
              .container {
                max-width: 600px;
                margin: 0 auto;
                padding: 20px;
                background-color: #ffffff;
              }

              /* Encabezado */
              .header {
                text-align: center;
                margin-bottom: 20px;
              }

              .header h1 {
                color: #333333;
                font-size: 24px;
              }

              /* Contenido */
              .content {
                padding: 20px;
                background-color: #f9f9f9;
              }

              .content p {
                color: #555555;
                font-size: 16px;
                line-height: 1.5;
                margin-bottom: 20px;
              }

              /* Botón de verificación */
              .verification-btn {
                display: inline-block;
                background-color: #4caf50;
                color: #ffffff;
                text-decoration: none;
                padding: 10px 20px;
                border-radius: 4px;
                font-size: 16px;
                position: relative; /* Agregamos posición relativa para posicionar la línea */
                overflow: hidden; /* Ocultamos parte de la línea que se sale del botón */
              }

              /* Animación de la línea */
              .verification-btn::after {
                content: "";
                position: absolute;
                top: 100%;
                left: 50%;
                width: 100%;
                height: 2px;
                background-color: black;
                transform: translate(-50%, -50%) scaleX(0);
                transform-origin: left;
                animation: lineAnimation 2s infinite; /* Configuramos la animación */
              }

              @keyframes lineAnimation {
                0% {
                  transform: translate(-50%, -50%) scaleX(0);
                  transform-origin: left;
                }
                50% {
                  transform: translate(-50%, -50%) scaleX(1);
                  transform-origin: left;
                }
                100% {
                  transform: translate(-50%, -50%) scaleX(0);
                  transform-origin: right;
                }
              }

              /* Pie de página */
              .footer {
                text-align: center;
                color: #777777;
                margin-top: 20px;
              }

              body {
            display: -webkit-box;
            display: flex;
            -webkit-box-pack: center;
                    justify-content: center;
            -webkit-box-align: center;
                    align-items: center;
            height: 100vh;
            background: #fcf3ec;
          }

          .button {
            --offset: 10px;
            --border-size: 2px;
            display: block;
            position: relative;
            padding: 1.5em 3em;
            -webkit-appearance: none;
              -moz-appearance: none;
                    appearance: none;
            border: 0;
            background: transparent;
            color: #e55743;
            text-transform: uppercase;
            letter-spacing: .25em;
            outline: none;
            cursor: pointer;
            font-weight: bold;
            border-radius: 0;
            box-shadow: inset 0 0 0 var(--border-size) currentcolor;
            -webkit-transition: background .8s ease;
            transition: background .8s ease;
            margin: auto;
          }
          .button:hover {
            background: rgba(100, 0, 0, 0.03);
          }
          .button__horizontal, .button__vertical {
            position: absolute;
            top: var(--horizontal-offset, 0);
            right: var(--vertical-offset, 0);
            bottom: var(--horizontal-offset, 0);
            left: var(--vertical-offset, 0);
            -webkit-transition: -webkit-transform .8s ease;
            transition: -webkit-transform .8s ease;
            transition: transform .8s ease;
            transition: transform .8s ease, -webkit-transform .8s ease;
            will-change: transform;
          }
          .button__horizontal::before, .button__vertical::before {
            content: '';
            position: absolute;
            border: inherit;
          }
          .button__horizontal {
            --vertical-offset: calc(var(--offset) * -1);
            border-top: var(--border-size) solid currentcolor;
            border-bottom: var(--border-size) solid currentcolor;
          }
          .button__horizontal::before {
            top: calc(var(--vertical-offset) - var(--border-size));
            bottom: calc(var(--vertical-offset) - var(--border-size));
            left: calc(var(--vertical-offset) * -1);
            right: calc(var(--vertical-offset) * -1);
          }
          .button:hover .button__horizontal {
            -webkit-transform: scaleX(0);
                    transform: scaleX(0);
          }
          .button__vertical {
            --horizontal-offset: calc(var(--offset) * -1);
            border-left: var(--border-size) solid currentcolor;
            border-right: var(--border-size) solid currentcolor;
          }
          .button__vertical::before {
            top: calc(var(--horizontal-offset) * -1);
            bottom: calc(var(--horizontal-offset) * -1);
            left: calc(var(--horizontal-offset) - var(--border-size));
            right: calc(var(--horizontal-offset) - var(--border-size));
          }
          .button:hover .button__vertical {
            -webkit-transform: scaleY(0);
                    transform: scaleY(0);
          }
            </style>
          </head>
          <body>
            <div class="container">
              <div class="header">
                <h1>Verificación de correo electrónico</h1>
              </div>
              <div class="content">
              ''' + "<p>Hola, " + name + '''
                                </p>
                <p>Gracias por registrarte en FULL. Para completar el proceso de verificación de tu correo electrónico, haz clic en el siguiente botón:</p>
                <a href="">
                  <button class="button">
                    Verify email
                    <div class="button__horizontal"></div>
                    <div class="button__vertical"></div>
                  </button>
                </a>
              </div>
              <div class="footer">
                <p>No responda a este correo electrónico. Si necesita ayuda, contáctenos en fullenterprisesupport@gmail.com</p>
              </div>
            </div>
          </body>
          </html>          
          '''
                }
            ]
        }
        result = self.mailjet.send.create(data=data)

        return result.status_code

    def sendEmailChanged(self, email, name):
        data = {
            'Messages': [
                {
                    "From": {
                        "Email": "phermidagomez@gmail.com",
                        "Name": "FULL"
                    },
                    "To": [
                        {
                            "Email": email,
                            "Name": name
                        }
                    ],
                    "Subject": "Cambio de correo electrónico",
                    "HTMLPart": '''
          <!DOCTYPE html>
          <html>
          <head>
            <meta charset="UTF-8">
            <title>Cambio de correo electrónico</title>
            <style>
              /* Estilos generales */
              body {
                font-family: Arial, sans-serif;
                background-color: #f6f6f6;
                margin: 0;
                padding: 0;
              }

              /* Contenedor principal */
              .container {
                max-width: 600px;
                margin: 0 auto;
                padding: 20px;
                background-color: #ffffff;
              }

              /* Encabezado */
              .header {
                text-align: center;
                margin-bottom: 20px;
              }

              .header h1 {
                color: #333333;
                font-size: 24px;
              }

              /* Contenido */
              .content {
                padding: 20px;
                background-color: #f9f9f9;
              }

              .content p {
                color: #555555;
                font-size: 16px;
                line-height: 1.5;
                margin-bottom: 20px;
              }

              /* Botón de verificación */
              .verification-btn {
                display: inline-block;
                background-color: #4caf50;
                color: #ffffff;
                text-decoration: none;
                padding: 10px 20px;
                border-radius: 4px;
                font-size: 16px;
              }

              /* Pie de página */
              .footer {
                text-align: center;
                color: #777777;
                margin-top: 20px;
              }
            </style>
          </head>
          <body>
            <div class="container">
              <div class="header">
                <h1>Cambio de correo electrónico</h1>
              </div>
              <div class="content">
                ''' + "<p>Hola, " + name + '''
                                </p>
                <p>Tu dirección de correo electrónico asociada a tu cuenta en FULL ha sido cambiada exitosamente.</p>
                <p>Si no has realizado este cambio, por favor contáctanos de inmediato para que podamos asistirte.</p>
                <p>Si has realizado el cambio, puedes ignorar este mensaje.</p>
              </div>
              <div class="footer">
                <p>No responda a este correo electrónico. Si necesita ayuda, contáctenos en fullenterprisesuport@gmail.com</p>
              </div>
            </div>
          </body>
          </html>
          '''
                }
            ]
        }
        result = self.mailjet.send.create(data=data)

        return result.status_code

    def sendPhoneChanged(self, email, name):
        data = {
            'Messages': [
                {
                    "From": {
                        "Email": "phermidagomez@gmail.com",
                        "Name": "FULL"
                    },
                    "To": [
                        {
                            "Email": email,
                            "Name": name
                        }
                    ],
                    "Subject": "Cambio de teléfono",
                    "HTMLPart": '''
          <!DOCTYPE html>
          <html>
          <head>
            <meta charset="UTF-8">
            <title>Cambio de teléfono</title>
            <style>
              /* Estilos generales */
              body {
                font-family: Arial, sans-serif;
                background-color: #f6f6f6;
                margin: 0;
                padding: 0;
              }

              /* Contenedor principal */
              .container {
                max-width: 600px;
                margin: 0 auto;
                padding: 20px;
                background-color: #ffffff;
              }

              /* Encabezado */
              .header {
                text-align: center;
                margin-bottom: 20px;
              }

              .header h1 {
                color: #333333;
                font-size: 24px;
              }

              /* Contenido */
              .content {
                padding: 20px;
                background-color: #f9f9f9;
              }

              .content p {
                color: #555555;
                font-size: 16px;
                line-height: 1.5;
                margin-bottom: 20px;
              }

              /* Botón de verificación */
              .verification-btn {
                display: inline-block;
                background-color: #4caf50;
                color: #ffffff;
                text-decoration: none;
                padding: 10px 20px;
                border-radius: 4px;
                font-size: 16px;
              }

              /* Pie de página */
              .footer {
                text-align: center;
                color: #777777;
                margin-top: 20px;
              }
            </style>
          </head>
          <body>
            <div class="container">
              <div class="header">
                <h1>Cambio de telefono</h1>
              </div>
              <div class="content">
                ''' + "<p>Hola, " + name + '''
                                </p>
                <p>Tu número de telefono asociado a tu cuenta en FULL ha sido cambiado exitosamente.</p>
                <p>Si no has realizado este cambio, por favor contáctanos de inmediato para que podamos asistirte.</p>
                <p>Si has realizado el cambio, puedes ignorar este mensaje.</p>
              </div>
              <div class="footer">
                <p>No responda a este correo electrónico. Si necesita ayuda, contáctenos en fullenterprisesuport@gmail.com</p>
              </div>
            </div>
          </body>
          </html>
          '''
                }
            ]
        }
        result = self.mailjet.send.create(data=data)

        return result.status_code

    def sendPasswordChanged(self, email, name):
        data = {
            'Messages': [
                {
                    "From": {
                        "Email": "phermidagomez@gmail.com",
                        "Name": "FULL"
                    },
                    "To": [
                        {
                            "Email": email,
                            "Name": name
                        }
                    ],
                    "Subject": "Cambio de contraseña",
                    "HTMLPart": '''
          <!DOCTYPE html>
          <html>
          <head>
            <meta charset="UTF-8">
            <title>Cambio de contraseña</title>
            <style>
              /* Estilos generales */
              body {
                font-family: Arial, sans-serif;
                background-color: #f6f6f6;
                margin: 0;
                padding: 0;
              }

              /* Contenedor principal */
              .container {
                max-width: 600px;
                margin: 0 auto;
                padding: 20px;
                background-color: #ffffff;
              }

              /* Encabezado */
              .header {
                text-align: center;
                margin-bottom: 20px;
              }

              .header h1 {
                color: #333333;
                font-size: 24px;
              }

              /* Contenido */
              .content {
                padding: 20px;
                background-color: #f9f9f9;
              }

              .content p {
                color: #555555;
                font-size: 16px;
                line-height: 1.5;
                margin-bottom: 20px;
              }

              /* Botón de verificación */
              .verification-btn {
                display: inline-block;
                background-color: #4caf50;
                color: #ffffff;
                text-decoration: none;
                padding: 10px 20px;
                border-radius: 4px;
                font-size: 16px;
              }

              /* Pie de página */
              .footer {
                text-align: center;
                color: #777777;
                margin-top: 20px;
              }
            </style>
          </head>
          <body>
            <div class="container">
              <div class="header">
                <h1>Cambio de contraseña</h1>
              </div>
              <div class="content">
                ''' + "<p>Hola, " + name + '''
                                </p>
                <p>Tu contraseña asociada a tu cuenta en FULL ha sido cambiado exitosamente.</p>
                <p>Si no has realizado este cambio, por favor contáctanos de inmediato para que podamos asistirte.</p>
                <p>Si has realizado el cambio, puedes ignorar este mensaje.</p>
              </div>
              <div class="footer">
                <p>No responda a este correo electrónico. Si necesita ayuda, contáctenos en fullenterprisesuport@gmail.com</p>
              </div>
            </div>
          </body>
          </html>
          '''
                }
            ]
        }
        result = self.mailjet.send.create(data=data)

        return result.status_code

    def sendTokenSended(self, email, name, token):
        data = {
            'Messages': [
                {
                    "From": {
                        "Email": "phermidagomez@gmail.com",
                        "Name": "FULL"
                    },
                    "To": [
                        {
                            "Email": email,
                            "Name": name
                        }
                    ],
                    "Subject": "Token de verificación",
                    "HTMLPart": '''
          <!DOCTYPE html>
          <html>
          <head>
            <meta charset="UTF-8">
            <title>Token de verificacion</title>
            <style>
              /* Estilos generales */
              body {
                font-family: Arial, sans-serif;
                background-color: #f6f6f6;
                margin: 0;
                padding: 0;
              }

              /* Contenedor principal */
              .container {
                max-width: 600px;
                margin: 0 auto;
                padding: 20px;
                background-color: #ffffff;
              }

              /* Encabezado */
              .header {
                text-align: center;
                margin-bottom: 20px;
              }

              .header h1 {
                color: #333333;
                font-size: 24px;
              }

              /* Contenido */
              .content {
                padding: 20px;
                background-color: #f9f9f9;
              }

              .content p {
                color: #555555;
                font-size: 16px;
                line-height: 1.5;
                margin-bottom: 20px;
              }

              /* Botón de verificación */
              .verification-btn {
                display: inline-block;
                background-color: #4caf50;
                color: #ffffff;
                text-decoration: none;
                padding: 10px 20px;
                border-radius: 4px;
                font-size: 16px;
              }

              /* Pie de página */
              .footer {
                text-align: center;
                color: #777777;
                margin-top: 20px;
              }

              .tokenClass {
                padding: 10px;
                background-color: gray;
                color: white !important;
                text-align: center;
                border-radius: 10px;
              }

            </style>
          </head>
          <body>
            <div class="container">
              <div class="header">
                <h1>Token de verificacion</h1>
              </div>
              <div class="content">
                ''' + "<p>Hola, " + name + '''
                                </p>
                <p>Este es el token a utilizar.</p>
                ''' + "<p class='tokenClass'>" + token + '''
                                </p>
              </div>
              <div class="footer">
                <p>No responda a este correo electrónico. Si necesita ayuda, contáctenos en fullenterprisesuport@gmail.com</p>
              </div>
            </div>
          </body>
          </html>
          '''
                }
            ]
        }
        result = self.mailjet.send.create(data=data)

        return result.status_code
# print(result.status_code)
# print(result.json())
