import logging
import psycopg2
import os
import ssl
import secrets
import smtplib
import logging
from email.message import EmailMessage
from typing import Optional
from dotenv import load_dotenv

from fastapi import FastAPI, Depends, HTTPException, status, File, UploadFile, Form
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
from pydantic import BaseModel
from passlib.context import CryptContext
import psycopg2

from database import obter_conexao

logger = logging.getLogger("uvicorn.error")
# Carrega as variáveis de ambiente (.env)
load_dotenv()

app = FastAPI(title="API Completa TVC - Autenticação & Reports", redirect_slashes=False)

# Diretório para uploads de relatórios no servidor
UPLOAD_DIR = "uploads"
if not os.path.exists(UPLOAD_DIR):
    os.makedirs(UPLOAD_DIR)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], 
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def enviar_email_com_botao(email_destino: str, token: str):
    remetente = os.getenv("GMAIL_USER")
    palavra_passe_app = os.getenv("GMAIL_PASS")
    api_url = os.getenv("API_URL")

    if not remetente:
        raise RuntimeError("GMAIL_USER não configurada no servidor.")

    if not palavra_passe_app:
        raise RuntimeError("GMAIL_PASS não configurada no servidor.")

    if not api_url:
        raise RuntimeError("API_URL não configurada no servidor.")

    # Remove os espaços de apresentação da password de aplicação.
    palavra_passe_app = palavra_passe_app.replace(" ", "").strip()

    link_ativacao = (
        f"{api_url.rstrip('/')}/api/confirmar?token={token}"
    )

    msg = EmailMessage()
    msg["From"] = remetente
    msg["To"] = email_destino
    msg["Subject"] = "Ative a sua conta - TVC App"

    corpo_html = f"""
    <!DOCTYPE html>
    <html lang="pt">
      <head>
        <meta charset="UTF-8">
      </head>
      <body style="
          font-family: Arial, sans-serif;
          text-align: center;
          padding: 40px;
          background-color: #f4f6f9;
      ">
        <div style="
            max-width: 500px;
            margin: 0 auto;
            background: white;
            padding: 30px;
            border-radius: 10px;
        ">
          <h2>Bem-vindo à nossa aplicação!</h2>

          <p>
            Falta apenas um passo para ativar a sua conta.
            Clique no botão abaixo:
          </p>

          <p>
            <a href="{link_ativacao}"
               style="
                   background-color: #3498db;
                   color: white;
                   padding: 14px 28px;
                   text-decoration: none;
                   border-radius: 5px;
                   font-weight: bold;
                   display: inline-block;
               ">
              ATIVAR MINHA CONTA
            </a>
          </p>

          <p>Se o botão não funcionar, copie este link:</p>

          <p style="word-break: break-all;">
            {link_ativacao}
          </p>
        </div>
      </body>
    </html>
    """

    msg.set_content(
        "Bem-vindo! Aceda ao link seguinte para ativar a sua conta:\n"
        + link_ativacao,
        charset="utf-8",
    )

    msg.add_alternative(
        corpo_html,
        subtype="html",
        charset="utf-8",
    )

    try:
        with smtplib.SMTP(
            "smtp.gmail.com",
            587,
            timeout=20,
        ) as server:
            server.starttls(context=ssl.create_default_context())
            server.login(remetente, palavra_passe_app)
            server.send_message(msg)

        logger.info("EMAIL: mensagem entregue ao servidor SMTP.")

    except Exception:
        logger.exception("EMAIL: falha no envio da mensagem.")
        raise

# ----------------------------------------------------
# MODELOS DE DADOS
# ----------------------------------------------------
class UtilizadorRegisto(BaseModel):
    username: str
    email: str
    password: str

class UtilizadorLogin(BaseModel):
    email: str
    password: str


# ----------------------------------------------------
# 1. ROTA DE REGISTO (POST)
# ----------------------------------------------------
@app.post("/api/registo", status_code=status.HTTP_201_CREATED)
def registar_utilizador(
    dados: UtilizadorRegisto,
    db=Depends(obter_conexao),
):
    username = dados.username.strip()
    email = dados.email.strip()
    password = dados.password

    if not username or not email or not password:
        raise HTTPException(
            status_code=400,
            detail="Preencha o nome, o email e a password.",
        )

    try:
        password_hash = pwd_context.hash(password)

        with db.cursor() as cursor:
            cursor.execute(
                """
                INSERT INTO utilizadores (
                    username,
                    email,
                    password_hash,
                    confirmado,
                    token_confirmacao
                )
                VALUES (%s, %s, %s, FALSE, NULL)
                RETURNING id, username, email;
                """,
                (
                    username,
                    email,
                    password_hash,
                ),
            )

            novo_utilizador = cursor.fetchone()

        db.commit()

    except psycopg2.errors.UniqueViolation:
        db.rollback()

        raise HTTPException(
            status_code=409,
            detail="O username ou email já estão em uso.",
        ) from None

    except Exception:
        logger.exception("REGISTO: falha ao criar o utilizador.")
        db.rollback()

        raise HTTPException(
            status_code=500,
            detail="Não foi possível criar a conta.",
        ) from None

    # Confirmação por email temporariamente desativada.
    # enviar_email_com_botao(email, token_seguro)

    return {
        "mensagem": "Conta criada com sucesso! Já pode iniciar sessão.",
        "utilizador": novo_utilizador,
    }

# ----------------------------------------------------
# 2. ROTA DE ATIVAÇÃO VIA LINK (GET)
# ----------------------------------------------------
@app.get("/api/confirmar", response_class=HTMLResponse)
def confirmar_conta_via_link(token: str, db = Depends(obter_conexao)):
    cursor = db.cursor()
    cursor.execute("SELECT id FROM utilizadores WHERE token_confirmacao = %s;", (token,))
    utilizador = cursor.fetchone()
    
    if not utilizador:
        return """
        <html>
            <body style="font-family: Arial, sans-serif; text-align: center; margin-top: 100px;">
                <h1 style="color: #e74c3c;">Erro de Ativação</h1>
                <p>Este link de confirmação é inválido ou já foi utilizado.</p>
            </body>
        </html>
        """
        
    query_update = """
        UPDATE utilizadores 
        SET confirmado = TRUE, token_confirmacao = NULL 
        WHERE token_confirmacao = %s;
    """
    cursor.execute(query_update, (token,))
    db.commit()
    
    return """
    <html>
        <body style="font-family: Arial, sans-serif; text-align: center; margin-top: 100px; background-color: #f9f9f9;">
            <div style="max-width: 400px; margin: 0 auto; background: white; padding: 40px; border-radius: 8px; box-shadow: 0 4px 15px rgba(0,0,0,0.1);">
                <div style="font-size: 50px; color: #2ecc71; margin-bottom: 20px;">✓</div>
                <h1 style="color: #333;">Conta Confirmada!</h1>
                <p style="color: #666; font-size: 16px; line-height: 1.5;">
                    O seu email foi verificado com sucesso. Já pode voltar à aplicação e efetuar o login.
                </p>
            </div>
        </body>
    </html>
    """


# ----------------------------------------------------
# 3. ROTA DE LOGIN (POST) - Corrigida para tuplos psycopg2
# ----------------------------------------------------
@app.post("/api/login")
def login_utilizador(
    dados: UtilizadorLogin,
    db=Depends(obter_conexao),
):
    with db.cursor() as cursor:
        cursor.execute(
            """
            SELECT id, username, email, password_hash
            FROM utilizadores
            WHERE email = %s;
            """,
            (dados.email.strip(),),
        )

        utilizador = cursor.fetchone()

    if not utilizador:
        raise HTTPException(
            status_code=401,
            detail="Credenciais inválidas.",
        )

    password_valida = pwd_context.verify(
        dados.password,
        utilizador["password_hash"],
    )

    if not password_valida:
        raise HTTPException(
            status_code=401,
            detail="Credenciais inválidas.",
        )

    # Confirmação por email temporariamente desativada.
    # if not utilizador["confirmado"]:
    #     raise HTTPException(
    #         status_code=403,
    #         detail="Confirme primeiro a sua conta através do email.",
    #     )

    return {
        "mensagem": "Login efetuado com sucesso!",
        "utilizador": {
            "id": utilizador["id"],
            "username": utilizador["username"],
            "email": utilizador["email"],
        },
    }

@app.post("/api/reports", status_code=status.HTTP_201_CREATED)
async def criar_report(
    utilizador_id: int = Form(...),
    titulo: str = Form(...),
    comentario: Optional[str] = Form(None),
    nivel_urgencia: str = Form(...),
    gravidade: int = Form(...),
    latitude: float = Form(...),
    longitude: float = Form(...),
    foto_1: Optional[UploadFile] = File(None),
    foto_2: Optional[UploadFile] = File(None),
    foto_3: Optional[UploadFile] = File(None),
    video: Optional[UploadFile] = File(None),
    db = Depends(obter_conexao)
):
    ficheiros_salvos = {"foto_1": None, "foto_2": None, "foto_3": None, "video": None}
    lista_uploads = [("foto_1", foto_1), ("foto_2", foto_2), ("foto_3", foto_3), ("video", video)]

    for chave, ficheiro in lista_uploads:
        if ficheiro and ficheiro.filename:
            # Extrai a extensão original de forma limpa (ex: .jpg)
            extensao = os.path.splitext(ficheiro.filename)[1]
            nome_unico = f"{secrets.token_hex(8)}{extensao}"
            caminho_completo = os.path.join(UPLOAD_DIR, nome_unico)
            
            try:
                conteudo = await ficheiro.read()
                with open(caminho_completo, "wb") as f:
                    f.write(conteudo)
                ficheiros_salvos[chave] = caminho_completo
            except Exception as e:
                raise HTTPException(status_code=500, detail=f"Falha ao guardar ficheiro {chave}: {str(e)}")

    cursor = db.cursor()
    try:
        query = """
            INSERT INTO reports (
                utilizador_id, titulo, comentario, nivel_urgencia, gravidade, 
                latitude, longitude, foto_1_url, foto_2_url, foto_3_url, video_url
            )
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            RETURNING id, titulo, criado_em;
        """
        valores = (
            utilizador_id, titulo, comentario, nivel_urgencia, gravidade,
            latitude, longitude, 
            ficheiros_salvos["foto_1"], ficheiros_salvos["foto_2"], ficheiros_salvos["foto_3"], 
            ficheiros_salvos["video"]
        )
        
        cursor.execute(query, valores)
        novo_report = cursor.fetchone()
        db.commit()
        
        # Desempacota o tuplo retornado pelo psycopg2 com segurança
        report_id, report_titulo, report_criado_em = novo_report
        
        return {
            "mensagem": "Report submetido com sucesso no servidor online!",
            "report": {
                "id": report_id,
                "titulo": report_titulo,
                "criado_em": str(report_criado_em)
            }
        }
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Erro na base de dados: {str(e)}")



@app.get("/api/verificar-estado")
def verificar_estado(
    email: str,
    db=Depends(obter_conexao),
):
    with db.cursor() as cursor:
        cursor.execute(
            """
            SELECT confirmado
            FROM utilizadores
            WHERE email = %s;
            """,
            (email.strip(),),
        )

        utilizador = cursor.fetchone()

    # Não devolve dados pessoais nem distingue
    # uma conta inexistente de uma conta não confirmada.
    confirmado = (
        bool(utilizador["confirmado"])
        if utilizador is not None
        else False
    )

    return {"confirmado": confirmado}
# ----------------------------------------------------
# INICIALIZAÇÃO DO SERVIDOR (Abre para a rede ou internet)
# ----------------------------------------------------
if __name__ == "__main__":
    import uvicorn
    # Em produção o uvicorn lê a porta dinamicamente definida pelo servidor (ex: Render/Railway)
    porta = int(os.getenv("PORT", 8000))
    uvicorn.run("main:app", host="0.0.0.0", port=porta, reload=False)