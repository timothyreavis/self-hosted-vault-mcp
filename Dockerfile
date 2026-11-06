FROM python:3.12-slim@sha256:4840d514c583a4d3d8cad3940e68dee6f0f6f3635c12fcd0a3d74c21a5b93a54
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 HOME=/tmp
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir --index-url https://pypi.org/simple --require-hashes -r requirements.txt \
    && groupadd -g 10001 vault-mcp \
    && useradd -u 10001 -g 10001 -M -s /usr/sbin/nologin vault-mcp
COPY vault_mcp ./vault_mcp
COPY LICENSE NOTICE ./
USER 10001:10001
CMD ["python", "-m", "vault_mcp"]
