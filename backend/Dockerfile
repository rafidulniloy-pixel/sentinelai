FROM python:3.13-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

# Dependencies are installed BEFORE the source is copied in, so editing
# main.py rebuilds in seconds instead of reinstalling every package.
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir -r requirements.txt

COPY . .

# Run as a non-root user - basic hardening, costs nothing.
RUN useradd --create-home --uid 1000 sentinel \
    && chown -R sentinel:sentinel /app
USER sentinel

EXPOSE 8000

# --host 0.0.0.0 is REQUIRED in a container. The default 127.0.0.1 only
# accepts connections from inside the container, so the port mapping
# would silently do nothing.
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
