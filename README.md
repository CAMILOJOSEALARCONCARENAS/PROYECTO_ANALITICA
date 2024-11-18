# Chatbot CRAISE - ProColombia

Este proyecto implementa **CRAISE** (Chatbot de Respuestas al Instante Sobre Exportaciones), un asistente virtual para apoyar a usuarios en consultas relacionadas con la exportación de productos desde Colombia. CRAISE utiliza **Streamlit** para su interfaz, **Snowflake** para gestionar la sesión y el almacenamiento de datos, y genera respuestas utilizando modelos de lenguaje alojados en el servicio **Cortex** de Snowflake.

## Características

- **Interfaz de Chat**: Permite a los usuarios hacer preguntas y recibir respuestas detalladas.
- **Contexto de Conversación**: Almacena y utiliza el historial de conversación del usuario.
- **Referencias**: Cada respuesta generada incluye referencias de los documentos de donde se extrajo la información.
- **Autenticación y Sesión Segura**: Utiliza JWT para autenticación en Snowflake.

## Requisitos Previos

Para ejecutar el proyecto, asegúrate de tener instalado:

- **Python 3.8 o superior**
- **Streamlit**
- **Snowflake Connector for Python** (`snowflake-connector-python`)
- **Snowflake Snowpark for Python** (`snowflake-snowpark-python`)
- **cryptography** (para gestionar claves y JWT)
- **requests** (para realizar llamadas HTTP a la API de Cortex)

## Instalación

1. **Clona el repositorio**:

    ```bash
    git clone https://github.com/tu_usuario/DOCUMENTOS-CRAISE.git
    cd DOCUMENTOS-CRAISE
    ```

2. **Instala las dependencias**:

    ```bash
    pip install -r requirements.txt
    ```

3. **Configura las credenciales**:

   Crea un archivo `CREDENCIAL.json` en el escritorio de tu sistema (`c:\Users\PGIC2\OneDrive - PROCOLOMBIA\Escritorio\CREDENCIALES`) con el siguiente formato:

    ```json
    {
        "ACCOUNT_SNOWFLAKE": "your_account",
        "USER_SNOWFLAKE": "your_user",
        "PASSWORD_SNOWFLAKE": "your_password",
        "ROLE_SNOWFLAKE": "your_role",
        "WAREHOUSE": "your_warehouse"
    }
    ```

4. **Agrega tu clave privada**:

   La clave privada debe guardarse en `C:\\Users\\PGIC2\\OneDrive - PROCOLOMBIA\\CAMILO ALARCON\\PROYECTOS IA\\DOCUMENTOS CRAISE\\Code\\tests\\rsa_key.pem`.

## Ejecución

Para iniciar el chatbot:

1. Abre una terminal en el directorio del proyecto.
2. Ejecuta el siguiente comando:

    ```bash
    streamlit run home.py
    ```

3. Accede a la aplicación en `http://localhost:8501`.

## Estructura Principal

### `main()` - Página Principal de la Aplicación

1. **Inicialización de Sesión**:
   - La función `init_snowflake_session()` se encarga de autenticar y crear la sesión de Snowflake usando JWT.

2. **Interfaz de Chat**:
   - Permite a los usuarios ingresar preguntas. El chatbot responde utilizando modelos de lenguaje y muestra el historial de chat para mantener el contexto de la conversación.

3. **Generación de Respuestas**:
   - `create_prompt` combina la pregunta del usuario con el contexto de documentos de Cortex para generar respuestas.
   - `complete` realiza la llamada al modelo Cortex seleccionado para generar la respuesta.

4. **Referencias**:
   - Al final de cada respuesta, se agrega una sección de referencias que lista los `RELATIVE_PATH` de los documentos consultados en el contexto.

### Funciones Clave

- **Autenticación y Sesión**:
  - `generate_jwt` y `get_session_token`: Generan el token JWT y gestionan la autenticación en Snowflake.
  - `create_snowpark_session`: Crea y configura la sesión de Snowpark para interactuar con Snowflake.

- **Consulta y Generación de Respuestas**:
  - `query_cortex_search_service`: Realiza consultas en Cortex para obtener documentos de contexto relevantes.
  - `complete`: Llama al modelo Cortex con el prompt generado para producir una respuesta.
  - `make_cortex_request`: Gestiona las solicitudes directas al API de Cortex.

- **Registro de Actividad**:
  - `registrar_actividad`: Guarda en la base de datos cada pregunta del usuario y la respuesta del chatbot para fines de seguimiento y análisis.

## Configuración Adicional

- **Depuración**: Habilita `Modo depuración` en la barra lateral para ver los documentos de contexto y otros detalles.
- **Opciones Avanzadas**: Permite seleccionar el modelo, número de fragmentos de contexto y el historial de mensajes de chat que el chatbot utilizará en cada respuesta.

## Solución de Problemas

- **Error de SSL**: Asegúrate de que los certificados SSL estén configurados correctamente en tu sistema.
- **Error de Autenticación**: Verifica que las credenciales en `CREDENCIAL.json` y la clave privada estén configuradas correctamente.
- **Error al Conectar a Snowflake**: Confirma que tienes acceso a la red de Snowflake y que el `account_identifier` es correcto.

## Contribución

Si deseas contribuir a este proyecto, por favor abre un `Issue` o un `Pull Request` en el repositorio. 

---
