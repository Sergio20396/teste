import os
import secrets
import smtplib
from email.header import Header
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
    remetente = os.getenv("GMAIL_USER", "sergio.pt2005@gmail.com")
    palavra_passe_app = os.getenv("GMAIL_PASS")

    if not palavra_passe_app:
        print("-> [Erro] GMAIL_PASS não configurada no ficheiro .env!")
        return

    # Lê dinamicamente o domínio público do seu servidor online
    api_url = os.getenv("API_URL", "http://localhost:8000")
    link_ativacao = f"{api_url.rstrip('/')}/api/confirmar?token={token}"

    msg = EmailMessage()
    msg["From"] = remetente
    msg["To"] = email_destino
    msg["Subject"] = Header("Ative a sua conta - TVC App", "utf-8")

    corpo_html = f"""
    <!DOCTYPE html>
    <html lang="pt">
      <head>
        <meta charset="UTF-8">
      </head>
      <body style="font-family: Arial, sans-serif; text-align: center; padding: 40px; background-color: #f4f6f9;">
        <div style="max-width: 500px; margin: 0 auto; background: white; padding: 30px; border-radius: 10px; box-shadow: 0 4px 10px rgba(0,0,0,0.05);">
            <h2>Bem-vindo à nossa aplicação!</h2>
            <p>Falta apenas um passo para ativar a sua conta. Clique no botão abaixo:</p>
            <br>
            <a href="{link_ativacao}"
               style="background-color: #3498db; color: white; padding: 14px 28px; text-decoration: none; border-radius: 5px; font-weight: bold; display: inline-block;">
               ATIVAR MINHA CONTA
            </a>
            <br><br><br>
            <p style="color: #999; font-size: 12px;">Se o botão não funcionar, copie este link:</p>
            <p style="color: #3498db; font-size: 12px; word-break: break-all;">{link_ativacao}</p>
        </div>
      </body>
    </html>
    """

    msg.set_content(
        f"Bem-vindo! Aceda ao link seguinte para ativar a sua conta:\n{link_ativacao}",
        charset="utf-8"
    )
    msg.add_alternative(corpo_html, subtype="html", charset="utf-8")

    try:
        # CORRIGIDO: Agora aponta exatamente para o Host SMTP da Google
        server = smtplib.SMTP("smtp.gmail.com", 587, timeout=20)
        server.starttls()
        server.login(remetente, palavra_passe_app.strip())
        server.send_message(msg)
        server.quit()
        print(f"-> Email de ativação enviado com sucesso para {email_destino}!")
    except Exception as e:
        print(f"Erro ao enviar email para {email_destino}: {type(e).__name__}: {e}")


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
def registar_utilizador(dados: UtilizadorRegisto, db = Depends(obter_conexao)):
    cursor = db.cursor()
    password_hash = pwd_context.hash(dados.password)
    token_seguro = secrets.token_hex(16)
    
    try:
        query = """
            INSERT INTO utilizadores (username, email, password_hash, token_confirmacao)
            VALUES (%s, %s, %s, %s) RETURNING id, username, email;
        """
        cursor.execute(query, (dados.username, dados.email, password_hash, token_seguro))
        novo_utilizador = cursor.fetchone()
        db.commit()
        
        # Envia e-mail em segundo plano
        enviar_email_com_botao(dados.email, token_seguro)
        
        return {
            "mensagem": "Utilizador registado! Verifique a sua caixa de entrada para ativar a conta.",
            "utilizador": {"id": novo_utilizador[0], "username": novo_utilizador[1], "email": novo_utilizador[2]}
        }
    except psycopg2.errors.UniqueViolation:
        db.rollback()
        raise HTTPException(status_code=400, detail="O username ou email já estão em uso.")
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Erro interno: {str(e)}")


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
def login_utilizador(dados: UtilizadorLogin, db = Depends(obter_conexao)):
    cursor = db.cursor()
    # Mapeamento explícito das colunas criadas no banco
    cursor.execute("SELECT id, username, email, password_hash, confirmado FROM utilizadores WHERE email = %s;", (dados.email,))
    utilizador = cursor.fetchone()
    
    if not utilizador:
        raise HTTPException(status_code=401, detail="Credenciais inválidas.")
        
    db_id, db_username, db_email, db_password_hash, db_confirmado = utilizador
    
    if not db_confirmado:
        raise HTTPException(status_code=403, detail="Por favor, confirme a sua conta primeiro através do email.")
        
    password_valida = pwd_context.verify(dados.password, db_password_hash)
    if not password_valida:
        raise HTTPException(status_code=401, detail="Credenciais inválidas.")
        
    return {
        "mensagem": "Login efetuado com sucesso!", 
        "utilizador": {
            "id": db_id, 
            "username": db_username,
            "email": db_email
        }
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
def verificar_estado_utilizador(email: str, db = Depends(obter_conexao)):
    cursor = db.cursor()
    cursor.execute("SELECT confirmado FROM utilizadores WHERE email = %s;", (email,))
    resultado = cursor.fetchone()
    
    if not resultado:
        return {"confirmado": False}
        
    return {"confirmado": resultado[0]}
# ----------------------------------------------------
# INICIALIZAÇÃO DO SERVIDOR (Abre para a rede ou internet)
# ----------------------------------------------------
if __name__ == "__main__":
    import uvicorn
    # Em produção o uvicorn lê a porta dinamicamente definida pelo servidor (ex: Render/Railway)
    porta = int(os.getenv("PORT", 8000))
    uvicorn.run("main:app", host="0.0.0.0", port=porta, reload=False)