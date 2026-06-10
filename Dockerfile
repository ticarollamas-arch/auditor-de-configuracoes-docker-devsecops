FROM python:3.11-alpine

# Define o diretório de trabalho
WORKDIR /app

# Instala dependências necessárias
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copia o script e as regras de segurança
COPY auditor_passivo.py .
COPY rules/ ./rules/

# Cria um usuário não-root para execução segura da ferramenta
RUN addgroup -S devsecops && adduser -S devsecops -G devsecops
USER devsecops

# Define o ponto de entrada padrão
ENTRYPOINT ["python", "/app/auditor_passivo.py"]
CMD ["--help"]