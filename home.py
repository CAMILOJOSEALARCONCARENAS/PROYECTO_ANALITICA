import streamlit as st
import jwt
import time
import requests
from snowflake.snowpark import Session
import os
import json
from requests.exceptions import SSLError, HTTPError
import logging
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.hazmat.backends import default_backend
from datetime import datetime, timedelta, timezone
import base64
import hashlib
from snowflake.core import Root  # requiere snowflake>=0.8.0
#from snowflake.cortex import Complete
from snowflake.snowpark.context import get_active_session
from ConSnw import *


# Configurar el logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger()

# Función para calcular la huella digital de la clave pública
def calculate_public_key_fingerprint(private_key):
    public_key_raw = private_key.public_key().public_bytes(
        Encoding.DER, PublicFormat.SubjectPublicKeyInfo
    )
    sha256hash = hashlib.sha256()
    sha256hash.update(public_key_raw)
    return 'SHA256:' + base64.b64encode(sha256hash.digest()).decode('utf-8')

private_key_path = "C:\\Users\\PGIC2\\OneDrive - PROCOLOMBIA\\CAMILO ALARCON\\PROYECTOS IA\\DOCUMENTOS CRAISE\\Code\\tests\\rsa_key.pem"

# Función para preparar el `account_identifier` sin región/subdominio
def prepare_account_name_for_jwt(account_identifier):
    if '.global' not in account_identifier:
        idx = account_identifier.find('.')
        if idx > 0:
            account_identifier = account_identifier[:idx]
    return account_identifier.upper()

# Función para generar JWT
def generate_jwt(account_identifier, user, private_key_path):
    # Prepara el account_identifier sin región
    account = prepare_account_name_for_jwt(account_identifier)
    qualified_username = f"{account}.{user.upper()}"

    try:
        with open(private_key_path, 'rb') as key_file:
            pemlines = key_file.read()
            private_key = load_pem_private_key(pemlines, password=None, backend=default_backend())
    except Exception as e:
        st.error(f"Error al leer la clave privada: {e}")
        return None

    # Calcular la huella digital de la clave pública
    public_key_fp = calculate_public_key_fingerprint(private_key)

    # Crear el payload
    now = datetime.now(timezone.utc)
    payload = {
        "iss": f"{qualified_username}.{public_key_fp}",  # Emisor con fingerprint de clave pública
        "sub": qualified_username,                       # Sujeto
        "iat": now,                                      # Emisión
        "exp": now + timedelta(hours=1),                 # Expiración en 1 hora
    }

    try:
        jwt_token = jwt.encode(payload, private_key, algorithm="RS256")
        # Convertir a cadena si es necesario
        if isinstance(jwt_token, bytes):
            jwt_token = jwt_token.decode('utf-8')
        return jwt_token
    except Exception as e:
        st.error(f"Error al generar el JWT: {e}")
        return None

desktop_path = "c:\\Users\\PGIC2\\OneDrive - PROCOLOMBIA\\Escritorio\\CREDENCIALES"
json_file_path = os.path.join(desktop_path, "CREDENCIAL.json")

with open(json_file_path, 'r') as file:
    credentials = json.load(file)
    
# Definir los parámetros de conexión usando las credenciales
credentials = {
    "ACCOUNT_SNOWFLAKE": credentials.get("ACCOUNT_SNOWFLAKE"),
    "USER_SNOWFLAKE": credentials.get("USER_SNOWFLAKE"),
    "PASSWORD_SNOWFLAKE": credentials.get("PASSWORD_SNOWFLAKE"),
    "ROLE_SNOWFLAKE": credentials.get("ROLE_SNOWFLAKE"),
    "WAREHOUSE": credentials.get("WAREHOUSE")
}

def get_session_token(jwt_token, account_identifier, credentials):
    account = prepare_account_name_for_jwt(account_identifier)
    endpoint = f"https://{account_identifier}.snowflakecomputing.com/session/v1/login-request?warehouse={credentials['WAREHOUSE']}&role={credentials['ROLE_SNOWFLAKE']}"

    headers = {
        "Content-Type": "application/json"
    }

    data = {
        "data": {
            "LOGIN_NAME": credentials["USER_SNOWFLAKE"],
            "AUTHENTICATOR": "SNOWFLAKE_JWT",
            "TOKEN": jwt_token
        }
    }

    try:
        response = requests.post(endpoint, headers=headers, json=data, verify=True)
        response.raise_for_status()
        session_info = response.json()

        # Imprimir la respuesta completa para depuración
        print("Respuesta completa de Snowflake:", session_info)

        # Verificar si 'token' o 'masterToken' están en la respuesta y obtener el que esté presente
        if 'data' in session_info:
            session_token = session_info['data'].get('token') or session_info['data'].get('masterToken')
            if session_token:
                st.success("Token de sesión obtenido correctamente.")
                return session_token
            else:
                st.error("La respuesta no contiene un 'token' ni 'masterToken' utilizables.")
                return None
        else:
            st.error(f"La respuesta no contiene el campo 'data'. Respuesta completa: {session_info}")
            return None
    except SSLError as ssl_err:
        st.error(f"Error de SSL al obtener el token de sesión: {ssl_err}")
        return None
    except HTTPError as http_err:
        st.error(f"Error HTTP al obtener el token de sesión: {http_err} - Respuesta: {response.text}")
        return None
    except Exception as err:
        st.error(f"Ocurrió un error inesperado al obtener el token de sesión: {err}")
        try:
            st.error(f"Respuesta completa: {response.text}")
        except:
            pass
        return None


def create_snowpark_session(credentials):
    connection_parameters = {
        "account": credentials["ACCOUNT_SNOWFLAKE"],
        "user": credentials["USER_SNOWFLAKE"],
        "password": credentials.get("PASSWORD_SNOWFLAKE"),
        "role": credentials["ROLE_SNOWFLAKE"],
        "warehouse": credentials["WAREHOUSE"],
        "token": st.session_state.get("session_token")  
    }

    try:
        session = Session.builder.configs(connection_parameters).create()
        st.success("Sesión de Snowpark creada exitosamente.")
        session.sql("USE DATABASE CORTEX_SEARCH_TUTORIAL_DB;").collect()
        session.sql("USE SCHEMA PUBLIC;").collect()
        return session
    except Exception as e:
        st.error(f"Error al crear la sesión de Snowpark: {e}")
        return None
#
def init_snowflake_session():
    account_identifier = "mp48210.us-east-2.aws"  # Reemplaza con tu `account_identifier`
    user = "Camilo"
    private_key_path = "C:\\Users\\PGIC2\\OneDrive - PROCOLOMBIA\\CAMILO ALARCON\\PROYECTOS IA\\DOCUMENTOS CRAISE\\Code\\tests\\rsa_key.pem"
    
    # Cargar las credenciales desde un archivo JSON
    json_file_path = "c:\\Users\\PGIC2\\OneDrive - PROCOLOMBIA\\Escritorio\\CREDENCIALES\\CREDENCIAL.json"
    
    try:
        with open(json_file_path, 'r') as file:
            credentials = json.load(file)
    except Exception as e:
        st.error(f"Error al cargar el archivo de credenciales: {e}")
        return False
    
    # Generar JWT
    st.write("Generando JWT...")
    jwt_token = generate_jwt(account_identifier, user, private_key_path)
    if not jwt_token:
        st.error("No se pudo generar el JWT.")
        return False
    st.success("JWT generado exitosamente.")
    
    # Obtener el token de sesión
    st.write("Obteniendo token de sesión...")
    session_token = get_session_token(jwt_token, account_identifier, credentials)
    
    if session_token:
        st.session_state["session_token"] = session_token
        st.write("Creando sesión de Snowpark...")
        snowpark_session = create_snowpark_session(credentials)
        if snowpark_session:
            st.session_state["snowpark_session"] = snowpark_session
            st.session_state["cortex_endpoint"] = f"https://{account_identifier}.snowflakecomputing.com/api/v2/cortex/inference:complete"
            st.success("Sesión de Snowpark creada y configurada correctamente.")
            return True
        else:
            st.error("No se pudo crear la sesión de Snowpark.")
            return False
    else:
        st.error("No se pudo obtener el token de sesión. Verifica las credenciales y la configuración.")
        return False

def get_snowpark_session():
    if "snowpark_session" not in st.session_state:
        st.session_state["snowpark_session"] = None
    return st.session_state["snowpark_session"]

def init_messages():
    if "clear_conversation" not in st.session_state:
        st.session_state.clear_conversation = False
    if st.session_state.clear_conversation or "messages" not in st.session_state:
        st.session_state.messages = []
        
def init_service_metadata():
    """
    Inicializa el estado de la sesión para los metadatos del servicio de búsqueda de Cortex.
    Consulta los servicios de búsqueda de Cortex disponibles desde la sesión de Snowflake y
    almacena sus nombres y columnas de búsqueda en el estado de la sesión.
    """
    if "service_metadata" not in st.session_state:
        snowpark_session = get_snowpark_session()
        services = snowpark_session.sql("SHOW CORTEX SEARCH SERVICES;").collect()
        service_metadata = []
        if services:
            for s in services:
                svc_name = s["name"]
                svc_search_col = snowpark_session.sql(
                    f"DESC CORTEX SEARCH SERVICE {svc_name};"
                ).collect()[0]["search_column"]
                service_metadata.append(
                    {"name": svc_name, "search_column": svc_search_col}
                )

        st.session_state.service_metadata = service_metadata

def init_config_options():
    """
    Inicializa las opciones de configuración en la barra lateral de Streamlit. Permite al usuario seleccionar
    un servicio de búsqueda de Cortex, limpiar la conversación, activar el modo de depuración,
    y activar el uso del historial del chat. También provee opciones avanzadas para seleccionar un modelo,
    el número de fragmentos de contexto y la cantidad de mensajes del chat a usar en el historial.
    """
    st.sidebar.selectbox(
        "Selecciona servicio de búsqueda de Cortex:",
        [s["name"] for s in st.session_state.service_metadata],
        key="selected_cortex_search_service",
    )

    st.sidebar.button("Limpiar conversación", key="clear_conversation")
    st.sidebar.toggle("Modo depuración", key="debug", value=False)
    st.sidebar.toggle("Usar historial de chat", key="use_chat_history", value=True)

    st.sidebar.selectbox("Seleccionar modelo:", MODELS, key="model_name")
    st.sidebar.number_input(
        "Seleccionar número de fragmentos de contexto",
        value=5,
        key="num_retrieved_chunks",
        min_value=1,
        max_value=10,
    )
    st.sidebar.number_input(
        "Seleccionar número de mensajes a usar en el historial del chat",
        value=5,
        key="num_chat_messages",
        min_value=1,
        max_value=10,
    )

    # Agregar límite de tokens para la consulta
    st.sidebar.number_input(
        "Máximo de tokens para la consulta",
        value=100,
        key="max_query_tokens",
        min_value=1,
        max_value=32000,
    )

    # Agregar límite de tokens para la respuesta
    st.sidebar.number_input(
        "Máximo de tokens para la respuesta",
        value=500,
        key="max_response_tokens",
        min_value=1,
        max_value=32000,
    )

def limit_tokens(text, max_tokens):
    words = text.split()
    if len(words) > max_tokens:
        words = words[:max_tokens]
        text = ' '.join(words)
    return text

def snow_sql(cursor, sql):
     #Ejecutar la consulta SQL
     cursor.execute(sql)
     # Obtener los resultados de la consulta
     column_names = [desc[0] for desc in cursor.description]
     results = cursor.fetchall()
    
     
     return results
 

   
# Función para realizar la solicitud a Cortex
def make_cortex_request(session_token, endpoint, data, send_token_in_headers=True):
    if send_token_in_headers:
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {session_token}"  # Incluye el token en los headers
        }
        payload = {
            "model": data["model"],
            "prompt": data["prompt"]
        }
    else:
        headers = {
            "Content-Type": "application/json"
        }
        payload = {
            "session_token": session_token,  # Incluye el token en el cuerpo
            "inference_data": data          # Ajusta según lo que espera la API
        }
    
    try:
        response = requests.post(endpoint, headers=headers, json=payload, verify=True)
        response.raise_for_status()
        result = response.json()
        return result
    except SSLError as ssl_err:
        st.error(f"Error de SSL al realizar la solicitud a Cortex: {ssl_err}")
    except HTTPError as http_err:
        st.error(f"Error HTTP al realizar la solicitud a Cortex: {http_err} - Respuesta: {response.text}")
    except Exception as err:
        st.error(f"Ocurrió un error inesperado al realizar la solicitud a Cortex: {err}")
        
# Función para consultar el servicio de búsqueda Cortex
#def query_cortex_search_service(query, columns=[], filter={}):
    """
    Consulta el servicio de búsqueda de Cortex seleccionado con la consulta dada y recupera
    los documentos de contexto. Muestra los documentos de contexto en la barra lateral si el modo
    de depuración está habilitado. Devuelve los documentos de contexto como una cadena de texto.

    Args:
        query (str): La consulta para buscar en el servicio de búsqueda de Cortex.

    Returns:
        str: La cadena concatenada de los documentos de contexto.
    """
    snowpark_session = get_snowpark_session()
    if snowpark_session:
        try:
            
            db, schema = snowpark_session.get_current_database(), snowpark_session.get_current_schema()

            cortex_search_service = (
                snowpark_session.databases[db]
                .schemas[schema]
                .cortex_search_services[st.session_state.selected_cortex_search_service]
            )

            context_documents = cortex_search_service.search(
                query, columns=columns, filter=filter, limit=st.session_state.num_retrieved_chunks
            )
            results = context_documents.results

            service_metadata = st.session_state.service_metadata
            search_col = [
                s["search_column"] for s in service_metadata
                if s["name"] == st.session_state.selected_cortex_search_service
            ][0].lower()

            context_str = ""
            for i, r in enumerate(results):
                context_str += f"Context document {i+1}: {r[search_col]} \\n\\n"

            if st.session_state.debug:
                st.sidebar.text_area("Context documents", context_str, height=500)

            return context_str, results
        except Exception as e:
            st.error(f"Error al consultar el servicio de búsqueda Cortex: {e}")
            return "", []
    else:
        st.error("La sesión de Snowpark no está disponible.")
        return "", []

def query_cortex_search_service(query, columns=[], filter={}):
    """
    Consulta el servicio de búsqueda de Cortex seleccionado con la consulta dada y recupera
    los documentos de contexto. Muestra los documentos de contexto en la barra lateral si el modo
    de depuración está habilitado. Devuelve los documentos de contexto como una cadena de texto.

    Args:
        query (str): La consulta para buscar en el servicio de búsqueda de Cortex.
        columns (list): Columnas a seleccionar en los resultados.
        filter (dict): Filtros para aplicar en la consulta.

    Returns:
        str: La cadena concatenada de los documentos de contexto.
    """
    snowpark_session = get_snowpark_session()
    if snowpark_session:
        try:
             # Determinar qué columna usar para el contexto; usar la primera columna en 'columns' o una predeterminada
            search_col = columns[0] if columns else "RELATIVE_PATH" 
            # Ejecutar la consulta en el servicio Cortex (asumiendo que existe una tabla con los documentos de contexto)
            query_sql = f"""
            SELECT {', '.join(columns) if columns else '*'}
            FROM CORTEX_SEARCH_TUTORIAL_DB.PUBLIC.DOCS_CHUNKS_TABLE
            WHERE language = 'Spanish'
            LIMIT {st.session_state.num_retrieved_chunks}
            """
            context_documents = snowpark_session.sql(query_sql).collect()
            
            # Procesar los documentos de contexto
            context_str = ""
            for i, r in enumerate(context_documents):
                context_str += f"Context document {i+1}: {r[search_col]} \\n\\n"

            if st.session_state.debug:
                st.sidebar.text_area("Context documents", context_str, height=500)

            # Imprimir los documentos de contexto para depuración
            print("Contexto obtenido (solo en español):", context_documents)

            return context_str, context_documents
        except Exception as e:
            st.error(f"Error al consultar el servicio de búsqueda Cortex: {e}")
            return "", []
    else:
        st.error("La sesión de Snowpark no está disponible.")
        return "", []

MODELS = [
    "reka-core",
    "llama3.2-3b",
    "llama3.1-8b",
    "mistral-7b",
]

def registrar_actividad(sesion_activa, pregunta, respuesta):
    """
    Registra la actividad de preguntas y respuestas en la tabla SEGUIMIENTO_ACTIVIDAD.

    Args:
    - sesion_activa: Sesión activa de conexión a la base de datos.
    - pregunta (str): La pregunta hecha por el usuario.
    - respuesta (str): La respuesta generada por el asistente.
    """
    # Crear objeto de conexión
    conn = sesion_activa.connection
    try:
        # Crear consulta para el insert
        query_insert = f"""
        INSERT INTO CORTEX_SEARCH_TUTORIAL_DB.PUBLIC.SEGUIMIENTO_ACTIVIDAD (PREGUNTA, RESPUESTA, FECHA_HORA) 
        VALUES ('{pregunta}', '{respuesta}', CONVERT_TIMEZONE('America/Los_Angeles', 'America/Bogota', CURRENT_TIMESTAMP));
        """
        # Crear un cursor para ejecutar la consulta
        cur = conn.cursor()
        try:
            # Ejecutar la consulta SQL con los valores
            cur.execute(query_insert)
        finally:
            # Cerrar el cursor
            cur.close()
    # Error
    except Exception as e:
        st.write(f"Error al registrar actividad: {e}")

tt = 1
def complete(model, prompt, temperature=tt):
    """
    Genera una respuesta para el prompt dado utilizando el modelo especificado en Snowflake Cortex.

    Args:
        model (str): El nombre del modelo a utilizar para la generación.
        prompt (str): El prompt para generar la respuesta en formato de array JSON con role y content.
        temperature (float): Valor de temperatura para la generación del modelo.

    Returns:
        str: Solo la respuesta generada.
    """
    snowpark_session = get_snowpark_session()
    
    # Construir la consulta SQL para llamar a SNOWFLAKE.CORTEX.COMPLETE con prompt como array y options como objeto
    query = f"""
    SELECT SNOWFLAKE.CORTEX.COMPLETE(
        '{model}',
        ARRAY_CONSTRUCT(OBJECT_CONSTRUCT('role', 'user', 'content', '{prompt}')),
        OBJECT_CONSTRUCT('temperature', {temperature})
    ) AS RESPONSE
    """

    try:
        # Ejecutar la consulta y obtener el resultado
        result = snowpark_session.sql(query).collect()
        
        # Validar si result no está vacío y contiene 'RESPONSE'
        if result and 'RESPONSE' in result[0]:
            response_json = result[0]['RESPONSE']
            
            # Parsear el JSON de la respuesta para obtener solo el mensaje
            response_data = json.loads(response_json)
            response_message = response_data["choices"][0]["messages"]
            
            # Limitar los tokens en la respuesta si es necesario
            if response_message:
                response_message = limit_tokens(response_message, st.session_state.max_response_tokens)
                # Escapar caracteres especiales y retornar solo el mensaje
                return response_message.replace("$", "\$")
            else:
                print("No se recibió ninguna respuesta del modelo.")
                return "Respuesta no disponible."
        else:
            print("La consulta no devolvió resultados válidos.")
            return "Respuesta no disponible."

    except Exception as e:
        print(f"Ocurrió un error al ejecutar la función SNOWFLAKE.CORTEX.COMPLETE: {e}")
        return "Error al generar la respuesta."

# Función para obtener el historial de chat
def get_chat_history():
    """
    Recupera el historial del chat del estado de la sesión limitado a la cantidad de mensajes
    especificada por el usuario en las opciones de la barra lateral.

    Returns:
        list: La lista de mensajes del chat en el estado de la sesión.
    """
    start_index = max(
        0, len(st.session_state.messages) - st.session_state.num_chat_messages
    )
    return st.session_state.messages[start_index : len(st.session_state.messages)]


    """
    Genera una respuesta para el prompt dado utilizando el modelo especificado.

    Args:
        model (str): El nombre del modelo a utilizar para la generación.
        prompt (str): El prompt para generar la respuesta.

    Returns:
        str: La respuesta generada.
    """
    response = complete(model, prompt,temperature=tt)
    # Limitar los tokens de la respuesta generada
    response = limit_tokens(response, st.session_state.max_response_tokens)
    return response.replace("$", "\$")

def make_chat_history_summary(chat_history, question):
    """
    Genera un resumen del historial del chat combinado con la pregunta actual para extender el contexto de la consulta.
    Utiliza el modelo de lenguaje para generar este resumen.

    Args:
        chat_history (str): El historial del chat para incluir en el resumen.
        question (str): La pregunta actual del usuario para extender con el historial del chat.

    Returns:
        str: El resumen generado del historial del chat y la pregunta.
    """
    prompt = f"""
        [INST]
        Basado en el historial del chat a continuación y en la pregunta, genera una consulta que extienda la pregunta
        con el historial del chat proporcionado. La consulta debe estar en lenguaje natural.
        Responde solo con la consulta. No añadas ninguna explicación.

        <historial_chat>
        {chat_history}
        </historial_chat>
        <pregunta>
        {question}
        </pregunta>
        [/INST]
    """

    summary = complete(st.session_state.model_name, prompt,temperature=tt)

    if st.session_state.debug:
        st.sidebar.text_area(
            "Resumen del historial del chat", summary.replace("$", "\$"), height=150
        )

    return summary

# Función para crear el prompt para el modelo de lenguaje
def create_prompt(user_question):
    """
    Crea un prompt para el modelo de lenguaje combinando la pregunta del usuario con el contexto
    recuperado del servicio de búsqueda de Cortex y el historial del chat (si está habilitado).
    Formatea el prompt según el formato de entrada esperado por el modelo.

    Args:
        user_question (str): La pregunta del usuario para generar un prompt.

    Returns:
        str: El prompt generado para el modelo de lenguaje.
    """
    if st.session_state.use_chat_history:
        chat_history = get_chat_history()
        if chat_history:
            # Convertir el historial de mensajes a una cadena formateada
            chat_history_str = "\n".join([f"{msg['role']}: {msg['content']}" for msg in chat_history])
            question_summary = make_chat_history_summary(chat_history_str, user_question)
            prompt_context, results = query_cortex_search_service(
                question_summary,
                columns=["CHUNK", "FILE_URL", "RELATIVE_PATH"],
                filter={"@and": [{"@eq": {"language": "Spanish"}}]},
            )
        else:
            prompt_context, results = query_cortex_search_service(
                user_question,
                columns=["CHUNK", "FILE_URL", "RELATIVE_PATH"],
                filter={"@and": [{"@eq": {"language": "Spanish"}}]},
            )
            chat_history_str = ""
    else:
        prompt_context, results = query_cortex_search_service(
            user_question,
            columns=["CHUNK", "FILE_URL", "RELATIVE_PATH"],
            filter={"@and": [{"@eq": {"language": "Spanish"}}]},
        )
        chat_history_str = ""

    prompt = f"""
            [INST]
            Eres un asistente de chat de IA con capacidades de RAG. Cuando un usuario te haga una pregunta,
            también se te proporcionará contexto entre las etiquetas <contexto> y </contexto>. Usa ese contexto
            junto con el historial del chat proporcionado entre las etiquetas <historial_chat> y </historial_chat>
            para ofrecer un resumen que responda a la pregunta del usuario. Asegúrate de que la respuesta sea coherente,
            concisa y directamente relevante a la pregunta del usuario.

            Si el usuario hace una pregunta genérica que no puede ser respondida con el contexto o el historial del chat proporcionado,
            solo di "Apreciado usuario,
            De la manera más atenta y de acuerdo con su solicitud nos permitimos informarle que lamentablemente ProColombia no 
            cuenta con dicha información.
            Esperamos poderle colaborar en otra oportunidad.
            ".

            No digas cosas como "según el contexto proporcionado".

            <chat_history>
            {chat_history_str}
            </chat_history>
            <context>
            {prompt_context}
            </context>
            <question>
            {user_question}
            </question>
            [/INST]
            Answer:
            """
    return prompt, results

def get_special_response(user_question):
    """
    Retorna una respuesta especial si la pregunta del usuario es 'hola' o 'gracias'.
    
    Args:
        user_question (str): La pregunta del usuario.
    
    Returns:
        str or None: La respuesta especial o None si no hay coincidencia.
    """
    question_clean = user_question.strip().lower()
    
    if question_clean == "hola":
        return (
            "Hola, soy CRAISE (Chatbot de Respuestas al Instante Sobre Exportaciones), "
            "hago parte de ProColombia y estoy especializado en responder consultas sobre "
            "cómo exportar productos desde Colombia al exterior. También puedo brindarte el código "
            "de diversas subpartidas arancelarias, así como la sectorización de estas dentro de la entidad en un futuro cercano."
        )
    elif question_clean == "gracias":
        return (
            "Con mucho gusto, para mí fue un placer ayudarte con tus consultas. "
            "Acá estaré siempre disponible para responder tus dudas."
        )
    else:
        return None



# Función principal de la aplicación Streamlit
def main():
    st.title(f":world_map: Chatbot CRAISE ProColombia ")

    # Inicializar la sesión de Snowflake
    with st.spinner("Inicializando la sesión con Snowflake..."):
        session_initialized = init_snowflake_session()
    

    
    
    if not session_initialized:
        st.error("No se pudo inicializar la sesión con Snowflake. Verifica las credenciales y la configuración.")
        return

    # Inicializar mensajes y metadatos de servicios
    init_service_metadata()
    init_config_options()
    init_messages()

    icons = {"assistant": "🔍", "user": "👤"}

    # Mostrar mensajes del historial de chat al volver a cargar la aplicación
    for message in st.session_state.messages:
        with st.chat_message(message["role"], avatar=icons[message["role"]]):
            st.markdown(message["content"])

    disable_chat = (
        "service_metadata" not in st.session_state
        or len(st.session_state.service_metadata) == 0
    )
    if question := st.chat_input("Haz una pregunta...", disabled=disable_chat):
        # Limitar los tokens de la pregunta del usuario
        question = limit_tokens(question, st.session_state.max_query_tokens)

        # Agregar mensaje del usuario al historial del chat
        st.session_state.messages.append({"role": "user", "content": question})
        # Mostrar mensaje del usuario en el contenedor de mensajes del chat
        with st.chat_message("user", avatar=icons["user"]):
            st.markdown(question.replace("$", "\$"))

        # Verificar si la pregunta es una de las respuestas especiales
        special_response = get_special_response(question)
        if special_response:
            # Mostrar respuesta especial del asistente
            with st.chat_message("assistant", avatar=icons["assistant"]):
                message_placeholder = st.empty()
                message_placeholder.markdown(special_response)
            
            # Registrar la pregunta y respuesta en la tabla SEGUIMIENTO_ACTIVIDAD
            registrar_actividad(session, question, special_response)

            # Agregar la respuesta especial al historial de mensajes
            st.session_state.messages.append(
                {"role": "assistant", "content": special_response}
            )
        else:
            # Mostrar respuesta del asistente en el contenedor de mensajes del chat
            with st.chat_message("assistant", avatar=icons["assistant"]):
                message_placeholder = st.empty()
                # Crear y mostrar la barra de progreso simulada
                progress_placeholder = st.empty()
                progress_bar = progress_placeholder.progress(0)
                with st.spinner('Generando respuesta a su consulta, por favor espere...'):
                    try:
                        progress_bar.progress(5)
                        status_text = st.empty()
                        question_original = question  # Guardar la pregunta original
                        question = question.replace("'", "")
                        prompt, results = create_prompt(question)
                    
                        progress_bar.progress(15)
                        # Generar la respuesta y obtener los detalles adicionales
                        generated_response = complete(
                            st.session_state.model_name, prompt,temperature=tt)

                        progress_bar.progress(75)
                        
                        # Verificar si la pregunta incluye "subpartida arancelaria"
                        if "subpartida" in question_original.lower():
                            nota_aclaratoria = (
                                "\n\n**Nota:** Debes tener en cuenta que en Colombia el ente regulador que brinda esta información es la DIAN. "
                                "Si necesitas exportar desde Colombia debes tener en cuenta la subpartida arancelaria a 10 dígitos; "
                                "para los otros países debes tener en cuenta solo los 6 primeros dígitos y revisar la entidad encargada de manejar esta información según corresponda."
                            )
                            
                        else: nota_aclaratoria = ""  
                        
                        final_response = generated_response + nota_aclaratoria
                        message_placeholder.markdown(final_response) 
                        
                        # Crear la sección de referencias
                        referencias = "\n\n**Referencias:**\n"
                        for doc in results:
                            if 'RELATIVE_PATH' in doc:  # Verificar que 'relative_path' esté disponible en el documento
                                referencias += f"- {doc['RELATIVE_PATH']}\n" 
        
                        
        
                        # Actualizar el estado de la barra de progreso a 100%
                        progress_bar.progress(100)
                        st.success("Respuesta Generada con éxito!")

                    except Exception as e:
                        # Mostrar mensaje de error en caso de excepción
                        st.error(f"Se produjo un error durante la generación del documento: {e}")
                        final_response = "Respuesta no disponible"  # Asignar respuesta por defecto en caso de error
                    finally:
                        # Finalizar barra de progreso
                        progress_bar.empty()
                
            # Registrar la pregunta y respuesta en la tabla SEGUIMIENTO_ACTIVIDAD, incluyendo modelo y tokens, si están disponibles
            registrar_actividad(session, question, final_response)

            # Agregar la respuesta generada al historial de mensajes
            st.session_state.messages.append(
                {"role": "assistant", "content": final_response}
            )

if __name__ == "__main__":
    session = session
    root = Root(session)
    main()