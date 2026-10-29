import logging
import os

import psycopg2
from psycopg2.extras import RealDictCursor
from dotenv import load_dotenv
from fastapi import HTTPException


load_dotenv()

logger = logging.getLogger(__name__)


def obter_conexao():
    conn = None

    try:
        conn = psycopg2.connect(
            host=os.environ["DB_HOST"],
            port=int(os.environ.get("DB_PORT", "5432")),
            dbname=os.environ.get("DB_NAME", "postgres"),
            user=os.environ["DB_USER"],
            password=os.environ["DB_PASSWORD"],
            sslmode="require",
            connect_timeout=15,
            cursor_factory=RealDictCursor,
        )
    except (psycopg2.Error, KeyError, ValueError):
        logger.exception("Falha ao estabelecer ligação à base de dados.")
        raise HTTPException(
            status_code=503,
            detail="Não foi possível ligar à base de dados.",
        ) from None

    try:
        yield conn
    finally:
        if conn is not None:
            conn.close()