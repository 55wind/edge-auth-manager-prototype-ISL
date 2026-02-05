# Deliverables Mapping (Prototype)

This repository provides the following deliverables:

## Software Package
- Lightweight Agent module package
  - register/discover/metadata transfer
  - async event loop + retry/backoff
  - mTLS client configuration
- Auth module API + Manager service package
  - /device/register, /device/approve, /auth/token, /auth/validate
  - /cert/issue, /cert/revoke, /cert/status (prototype status store)
- Message-bus secure channel library
  - TLS-enabled AMQP publisher with reconnect + local buffer
- Deployment/ops scripts
  - docker-compose stack
  - certificate generation script
  - RabbitMQ TLS config
- Sample client / demo scripts
  - agent runner
  - consumer demo
