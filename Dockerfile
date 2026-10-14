# ==============================================================================
# Lizenzmanager - Dockerfile
# Schlankes, sicheres Image auf Basis von Python 3.11-Slim
# ==============================================================================

FROM python:3.11-slim

# Umgebungsvariablen setzen:
# Keine .pyc-Dateien schreiben und Ausgaben direkt in stdout/stderr leiten
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PORT=5000 \
    HOST=0.0.0.0

WORKDIR /app

# Systempakete aktualisieren (optional für Sicherheit)
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Abhängigkeiten kopieren und installieren (nutzt Docker Layer-Caching)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Anwendungsquellcode kopieren
COPY . .

# Datenordner für die SQLite-Datenbank erstellen
RUN mkdir -p /app/data

# Port deklarieren
EXPOSE 5000

# Healthcheck prüfen
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD curl -f http://localhost:5000/ || exit 1

# Start via Gunicorn:
# 1 Worker mit 4 Threads ist optimal für SQLite-Gleichzeitigkeit
# Timeout 120s erlaubt längere KI-Rechnungsextraktionen ohne Abbruch
CMD ["gunicorn", "--bind", "0.0.0.0:5000", "--workers", "1", "--threads", "4", "--timeout", "120", "app:app"]
