FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app
COPY server/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY server/app ./app
COPY server/static ./static
RUN useradd -r shield && mkdir -p /data/storage && chown -R shield:shield /data
USER shield
ENV SHIELD_DATABASE_URL=sqlite:////data/shield.db SHIELD_STORAGE_ROOT=/data/storage \
    SHIELD_API_AUTH_MODE=local SHIELD_AUTHZ_MODE=local \
    SHIELD_ATTESTATION_MODE=production SHIELD_PLAY_INTEGRITY_MODE=production
EXPOSE 8000
CMD ["uvicorn","app.main:app","--host","0.0.0.0","--port","8000","--proxy-headers"]
