FROM python:3.11-slim

# Create non-root user for security
RUN groupadd -r manager && useradd -r -g manager -u 1001 manager

WORKDIR /app
COPY pyproject.toml /app/pyproject.toml
RUN pip install --no-cache-dir -U pip && pip install --no-cache-dir .

COPY services/manager /app

# Create data directory and set permissions
RUN mkdir -p /data && chown -R manager:manager /app /data

EXPOSE 8443

# Switch to non-root user
USER manager

CMD ["python", "-m", "manager.main"]
