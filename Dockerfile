FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 DATABASE_PATH=/data/app.db
RUN useradd --create-home --uid 10001 app && mkdir /data && chown app /data
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir fastapi pydantic uvicorn pyjwt argon2-cffi pyotp
COPY src ./src
USER app
VOLUME /data
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=3s CMD python -c "import urllib.request as u; u.urlopen('http://127.0.0.1:8000/health')"
CMD ["uvicorn", "main:app", "--app-dir", "src", "--host", "0.0.0.0", "--port", "8000"]
