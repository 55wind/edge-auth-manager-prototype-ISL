# Key Rotation Demo (Prototype)

This prototype demonstrates **non-disruptive reconnect + buffered publish** during TLS key rotation.

## Demo Steps
1. Start stack: `docker compose up --build`
2. Run agent and confirm messages are flowing in dashboard.
3. Replace RabbitMQ server cert files (simulating rotation) and restart only RabbitMQ:
   - `certs/rabbitmq/server.crt`
   - `certs/rabbitmq/server.key`
4. Agent publisher will:
   - detect AMQP disconnect
   - buffer outbound messages to `/buffer/unsent.jsonl`
   - reconnect with exponential backoff
   - flush buffered messages after reconnect

> Note: Full "hot reload" without broker restart depends on broker support and operator design. For this prototype, we restart RabbitMQ to simulate a cert rotation window.
