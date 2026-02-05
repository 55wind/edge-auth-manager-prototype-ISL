# Edge Device Auth Service Manager (Prototype)

This repository is a **prototype** implementation for:
- Lightweight **Agent security module** (register/discover/metadata transfer) with **async loop**, **retry/backoff**, and **mTLS session**.
- **Auth Manager API**: `/cert` (issue/renew/revoke), `/auth` (token/validate) + **approval gate**.
- **Message-bus secure channel**: TLS-enabled RabbitMQ, queue binding, reconnect + local buffer, keep working during key rotation.
- **Dashboard** (Streamlit) to verify end-to-end behavior.

> Target environments: Ubuntu 20.04+, CentOS 7.8+, Docker 28.4+, Kubernetes 1.30+ (prototype ships with docker-compose).

## Quickstart (Docker Compose)

### 1) Generate CA + certs (Manager/Admin/Agent)
```bash
cd ops
python gen_certs.py --out ../certs --cn-manager manager.local --cn-admin admin.local --cn-agent agent-001.local
```

### 2) Start services
```bash
cd ..
docker compose up --build
```

### 3) Set environment variables (optional)
```bash
# Copy example and customize if needed
cp .env.example .env
# Edit .env to set RABBITMQ_EDGE_PASSWORD (default: edge-secure-password-change-me)
```

### 4) Open dashboard
- Streamlit: http://localhost:8501
- Manager API: https://localhost:8443 (mTLS required)
- RabbitMQ Management: http://localhost:15672 (user: edge-agent, password: see .env)

### 5) Simulate an agent run (inside the agent container)
```bash
docker compose exec agent python -m agent.run --device-id agent-001 --site demo --group g1
```

## What to Verify in Dashboard
- **Device registration** appears as `PENDING`
- Approve the device (Admin action)
- Agent automatically obtains token and starts publishing **metadata** to RabbitMQ
- Dashboard shows recent messages and device status

## Compliance Verification

To verify all security requirements are met, run the automated compliance check:

```bash
bash ops/verify_compliance.sh
```

This will verify:
- ✅ Async agent with retry/backoff and mTLS
- ✅ All /auth and /cert API endpoints
- ✅ TLS-enforced message bus with buffering
- ✅ Non-root containers and security hardening

See `docs/COMPLIANCE.md` for detailed compliance documentation.

## Security Features

This prototype implements production-ready security practices:

- **mTLS**: All services communicate via mutual TLS authentication
- **Non-root containers**: All containers run as dedicated non-root users (UID 1001-1003)
- **TLS enforcement**: Manager (HTTPS only), RabbitMQ (TLS-only AMQP, TCP disabled)
- **No default credentials**: RabbitMQ `guest` user is deleted, dedicated `edge-agent` user created
- **Token refresh**: Agent automatically refreshes JWT tokens before expiration (at 80% TTL)
- **Approval gate**: Devices must be admin-approved before receiving tokens
- **Minimal permissions**: Each service runs with only required permissions

## Notes
- This is a prototype; storage is SQLite (mounted volume).
- Key rotation demo is implemented as "swap cert files + reload connections"; see `ops/rotate_demo.md`.
- All code comments are in English.
- For production deployment, replace SQLite with PostgreSQL and use proper secret management (e.g., HashiCorp Vault).
