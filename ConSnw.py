#!/usr/bin/env python
# coding: utf-8

# In[1]:


import pandas as pd
import numpy as np
import time
import re
import warnings
warnings.filterwarnings('ignore')
import unicodedata




# In[2]:


# Aumentar número de columnas que se pueden ver
pd.options.display.max_columns = None
# En los dataframes, mostrar los float con dos decimales
pd.options.display.float_format = '{:,.10f}'.format
# Cada columna será tan grande como sea necesario para mostrar todo su contenido
pd.set_option('display.max_colwidth', 0)


# In[ ]:


# Librerias necesarias para subir a Snowflake
import os
import json
import snowflake.connector 
#pip install snowflake-connector-python
from snowflake.connector.pandas_tools import write_pandas 
#pip install "snowflake-connector-python[pandas]"
from snowflake.snowpark import Session
from snowflake.connector import ProgrammingError
import PyPDF2
import io
import logging
import pandas as pd
from langchain.text_splitter import RecursiveCharacterTextSplitter


# In[4]:


# Paso 1: Definir la ruta al archivo JSON en el escritorio
desktop_path = "c:\\Users\\PGIC2\\OneDrive - PROCOLOMBIA\\Escritorio\\CREDENCIALES"
json_file_path = os.path.join(desktop_path, "CREDENCIAL.json")
json_file_path
 


# In[5]:


# Paso 2: Leer las credenciales desde el archivo JSON
with open(json_file_path, 'r') as file:
    credentials = json.load(file)
 
# Paso 3: Definir los parámetros de conexión usando las credenciales
connection_parameters = {
        "account": credentials["ACCOUNT_SNOWFLAKE"],
        "user": credentials["USER_SNOWFLAKE"],
        "password": credentials["PASSWORD_SNOWFLAKE"],
        "role": credentials["ROLE_SNOWFLAKE"],
        "warehouse": credentials["WAREHOUSE"]
    }
 
# Paso 5: Crear un objeto de conexión utilizando snowflake.connector
session = Session.builder.configs(connection_parameters).create()
print("Sesión actual:", {session})


# In[6]:


#Crear objeto de conexión llamado conn
conn=session.connection


# In[7]:


# Crear un cursor para ejecutar consultas (No olvidar cerrar el curso y la conexión al terminar el proces)
cur = conn.cursor()
cur


# In[8]:


# Asegurar que estamos en la ubicación que se desea para subir las bases de datos
cur.execute("SELECT CURRENT_WAREHOUSE() AS WAREHOUSE, CURRENT_DATABASE() AS DATABASE, CURRENT_SCHEMA() AS SCHEMA;")
cur.fetchone()


# In[9]:


def snow_sql(cursor, sql):
     #Ejecutar la consulta SQL
     cursor.execute(sql)
     # Obtener los resultados de la consulta
     column_names = [desc[0] for desc in cursor.description]
     results = cursor.fetchall()
    
     
     return results


# In[10]:


query = snow_sql(cur,"""
ALTER USER Camilo SET RSA_PUBLIC_KEY='MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA4+ECm6dpwM7GkQWlNkmo
V58h34LaAgyjmIZpFHwqilqZzl2l/5S2doA1q3khM8vjGkkt+cnTgSvomyGU+43Q
qKubxWjnoErV/JqspBgKhdmtwx92ED1ph0NU24fcXZTw+6bdUsdzLCi6uUnZg+i0
R84LlLnA2QIsKOCiFafOT9Qh58hjKLVrJ3DSzb5Ne1O2VBC20Z4EFi0MPj8Nry6F
lb03K6i/64JMcs2AJm/z7NdRSU7mf2ynyJKyDccyPQ10nkbpLW+fIrKdOyTWC3Xd
e0m82BlwCZMrwqso407RGii7qhUTzaaE7DDMFPW5f6VUlMGeG9VgFCVof1r9ROqW
IwIDAQAB';         
""")


# In[ ]:


#query



# In[36]:


query = snow_sql(cur,"""
ALTER ACCOUNT SET CORTEX_ENABLED_CROSS_REGION = 'AWS_US'         
""")


# In[37]:


query


# In[12]:


query = snow_sql(cur,"""
CREATE DATABASE IF NOT EXISTS cortex_search_tutorial_db           
""")


# In[ ]:


#query


# In[14]:


query = snow_sql(cur,"""
USE DATABASE cortex_search_tutorial_db               
""")


# In[ ]:


#query


# In[16]:


# Asegurar que estamos en la ubicación que se desea para subir las bases de datos
cur.execute("SELECT CURRENT_WAREHOUSE() AS WAREHOUSE, CURRENT_DATABASE() AS DATABASE, CURRENT_SCHEMA() AS SCHEMA;")
cur.fetchone()


# In[17]:


# Corrección de la consulta SQL
query = snow_sql(cur, """
    CREATE OR REPLACE STAGE cortex_search_tutorial_db.public.fomc
    DIRECTORY = (ENABLE = TRUE)
    ENCRYPTION = (TYPE = 'SNOWFLAKE_SSE')
""")


# In[ ]:


#query


# In[19]:


def upload_pdf_to_stage(connection, database, schema, stage, file_path):
    """
    Sube un archivo PDF a un stage en Snowflake con un nombre específico, sin compresión ni carpetas adicionales.

    Parámetros:
        connection (snowflake.connector.connection.SnowflakeConnection): Conexión activa de Snowflake.
        database (str): Nombre de la base de datos en Snowflake.
        schema (str): Nombre del esquema en Snowflake.
        stage (str): Nombre del stage en Snowflake.
        file_path (str): Ruta completa del archivo PDF a subir.
        snowflake_file_name (str): Nombre deseado para el archivo en Snowflake, sin extensión.

    Retorna:
        bool: True si la subida fue exitosa, False en caso de error.
    """
    try:
        # Verificar que el archivo sea un PDF
        if not file_path.lower().endswith('.pdf'):
            print("El archivo debe estar en formato PDF.")
            return False

        # Verificar que el archivo existe en el sistema de archivos
        if not os.path.exists(file_path):
            print(f"El archivo no existe en la ruta especificada: {file_path}")
            return False

        # Cambiar la base de datos y el esquema en Snowflake
        cur = connection.cursor()
        cur.execute(f"USE DATABASE {database};")
        cur.execute(f"USE SCHEMA {schema};")

        # Subir el archivo al stage con el nombre especificado, sin compresión
        stage_path = f"@{stage}"
        put_query = f"PUT 'file://{file_path}' {stage_path} AUTO_COMPRESS=FALSE OVERWRITE=TRUE"
        cur.execute(put_query)

        print(f"Archivo {file_path} subido exitosamente al stage '{stage}' como '{file_path}'.")
        return True

    except ProgrammingError as e:
        print(f"Error de programación en Snowflake: {e}")
        return False
    except Exception as e:
        print(f"Ocurrió un error: {e}")
        return False
    finally:
        cur.close()


# In[20]:


file_path1 = "C://Users//PGIC2//OneDrive - PROCOLOMBIA//CAMILO ALARCON//PROYECTOS IA//DOCUMENTOS CRAISE//Code//tests//MANUAL_RTAS_PREG_FREC_PROCOLOMBIA_Final2.pdf"


# In[21]:


file1 = upload_pdf_to_stage(conn, 'CORTEX_SEARCH_TUTORIAL_DB','PUBLIC','FOMC',file_path1)


# In[22]:


file_path2 = "C://Users//PGIC2//OneDrive - PROCOLOMBIA//CAMILO ALARCON//PROYECTOS IA//DOCUMENTOS CRAISE//Code//tests//sebsubsec.pdf"


# In[23]:


file2 = upload_pdf_to_stage(conn, 'CORTEX_SEARCH_TUTORIAL_DB','PUBLIC','FOMC',file_path2)


# In[27]:


query = snow_sql(cur, """
    CREATE OR REPLACE FUNCTION cortex_search_tutorial_db.public.pdf_text_chunker(file_url STRING)
    RETURNS TABLE (chunk VARCHAR)
    LANGUAGE PYTHON
    RUNTIME_VERSION = '3.9'
    HANDLER = 'pdf_text_chunker'
    PACKAGES = ('snowflake-snowpark-python', 'PyPDF2', 'langchain')
    AS
$$
from snowflake.snowpark.types import StringType, StructField, StructType
from langchain.text_splitter import RecursiveCharacterTextSplitter
from snowflake.snowpark.files import SnowflakeFile
import PyPDF2, io
import logging
import pandas as pd

class pdf_text_chunker:

    def read_pdf(self, file_url: str) -> str:
        logger = logging.getLogger("udf_logger")
        logger.info(f"Opening file {file_url}")

        with SnowflakeFile.open(file_url, 'rb') as f:
            buffer = io.BytesIO(f.readall())

        reader = PyPDF2.PdfReader(buffer)
        text = ""
        for page in reader.pages:
            try:
                text += page.extract_text().replace('\\n', ' ').replace('\\0', ' ')
            except:
                text = "Unable to Extract"
                logger.warn(f"Unable to extract from file {file_url}, page {page}")

        return text

    def process(self, file_url: str):
        text = self.read_pdf(file_url)

        text_splitter = RecursiveCharacterTextSplitter(
            chunk_size = 2000,  # Ajuste del tamaño del chunk
            chunk_overlap = 300,  # Superposición para mantener el contexto
            length_function = len
        )

        chunks = text_splitter.split_text(text)
        df = pd.DataFrame(chunks, columns=['chunk'])

        yield from df.itertuples(index=False, name=None)
$$
""")



# In[ ]:


#query


# In[29]:


# Corrección de la consulta SQL
query = snow_sql(cur, """
    CREATE OR REPLACE TABLE cortex_search_tutorial_db.public.docs_chunks_table AS
    SELECT
        relative_path,
        build_scoped_file_url(@cortex_search_tutorial_db.public.fomc, relative_path) AS file_url,
        -- preserve file title information by concatenating relative_path with the chunk
        CONCAT(relative_path, ': ', func.chunk) AS chunk,
        'English' AS language
    FROM
        directory(@cortex_search_tutorial_db.public.fomc),
        TABLE(cortex_search_tutorial_db.public.pdf_text_chunker(build_scoped_file_url(@cortex_search_tutorial_db.public.fomc, relative_path))) AS func;
""")


# In[ ]:


#query


# In[31]:


# Corrección de la consulta SQL
query = snow_sql(cur, """
    CREATE OR REPLACE CORTEX SEARCH SERVICE cortex_search_tutorial_db.public.fomc_meeting
    ON chunk
    ATTRIBUTES language
    WAREHOUSE = COMPUTE_WH
    TARGET_LAG = '1 hour'
    AS (
    SELECT
        chunk,
        relative_path,
        file_url,
        language
    FROM cortex_search_tutorial_db.public.docs_chunks_table
    );
""")


# In[ ]:


#query


# In[33]:


query = snow_sql(cur, """
CREATE OR REPLACE TABLE CORTEX_SEARCH_TUTORIAL_DB.PUBLIC.SEGUIMIENTO_ACTIVIDAD (
    ID NUMBER AUTOINCREMENT, 
    PREGUNTA VARCHAR, 
    RESPUESTA VARCHAR, 
    FECHA_HORA TIMESTAMP
)                 
""")


# In[ ]:


#query


# In[35]:


# Asegurar que estamos en la ubicación que se desea para subir las bases de datos
cur.execute("SELECT CURRENT_WAREHOUSE() AS WAREHOUSE, CURRENT_DATABASE() AS DATABASE, CURRENT_SCHEMA() AS SCHEMA;")
cur.fetchone()


# In[ ]:


#cerrar las conexiones para ahorrar creditos
#conn.close()
#cur.close()
#session.close()


# In[ ]:




