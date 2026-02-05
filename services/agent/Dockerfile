FROM python:3.11-slim

# Create non-root user for security
RUN groupadd -r agent && useradd -r -g agent -u 1002 agent

WORKDIR /app
COPY pyproject.toml /app/pyproject.toml
RUN pip install --no-cache-dir -U pip && pip install --no-cache-dir .

COPY services/agent /app

# Create buffer directory and set permissions
RUN mkdir -p /buffer && chown -R agent:agent /app /buffer

# Switch to non-root user
USER agent

CMD ["python", "-m", "agent.run", "--device-id", "agent-001", "--site", "demo", "--group", "g1"]
