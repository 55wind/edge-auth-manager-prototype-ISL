FROM python:3.11-slim

# Create non-root user for security
RUN groupadd -r dashboard && useradd -r -g dashboard -u 1003 dashboard

WORKDIR /app
COPY pyproject.toml /app/pyproject.toml
RUN pip install --no-cache-dir -U pip && pip install --no-cache-dir .

COPY services/dashboard /app

# Setup Streamlit config to disable telemetry (fixes container compatibility issues)
RUN mkdir -p /home/dashboard/.streamlit && \
    cp /app/.streamlit/config.toml /home/dashboard/.streamlit/config.toml

# Set permissions
RUN chown -R dashboard:dashboard /app /home/dashboard

EXPOSE 8501

# Switch to non-root user
USER dashboard

CMD ["streamlit", "run", "dashboard/app.py", "--server.port=8501", "--server.address=0.0.0.0"]
