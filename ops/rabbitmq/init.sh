#!/bin/bash
# RabbitMQ initialization script to create dedicated user and remove default guest account

set -e

# Wait for RabbitMQ to be ready
sleep 10

# Create dedicated isl user with restricted permissions
rabbitmqctl add_user isl "${RABBITMQ_EDGE_PASSWORD}"

# Restrict permissions: only configure/write/read on agent.* queues
# Configure: agent\.metadata   (can only declare agent.metadata queue)
# Write:     agent\.metadata   (can only publish to agent.metadata)
# Read:      agent\.metadata   (can only consume from agent.metadata)
rabbitmqctl set_permissions -p / isl "^agent\.metadata$" "^agent\.metadata$" "^agent\.metadata$"

# Delete default guest user for security
rabbitmqctl delete_user guest

echo "RabbitMQ security setup complete: isl user created with restricted permissions, guest user removed"
