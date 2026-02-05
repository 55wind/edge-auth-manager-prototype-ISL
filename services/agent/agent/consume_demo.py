from __future__ import annotations

import asyncio
import json
import os
import ssl
import aiormq

async def main():
    amqp_url = os.getenv("AMQP_URL", "amqps://guest:guest@localhost:5671/")
    certs_dir = os.getenv("CERTS_DIR", "./certs")
    ca_path = os.path.join(certs_dir, "rabbitmq", "ca.crt")

    ctx = ssl.create_default_context(cafile=ca_path)
    ctx.check_hostname = False

    conn = await aiormq.connect(amqp_url, ssl=ctx)
    ch = await conn.channel()
    await ch.queue_declare("agent.metadata", durable=True)

    async def on_message(message: aiormq.abc.DeliveredMessage):
        data = json.loads(message.body.decode("utf-8"))
        ts = data.get("ts", "?")
        device = data.get("device_id", "unknown")
        sensor = data.get("sensor_type", "")
        metrics = data.get("metrics", {})
        if sensor == "temperature":
            val = metrics.get("temperature_c", "?")
            print(f"[{ts}] {device} | TEMP  = {val} C")
        elif sensor == "humidity":
            val = metrics.get("humidity_pct", "?")
            print(f"[{ts}] {device} | HUMID = {val} %")
        else:
            print(data)
        await ch.basic_ack(message.delivery.delivery_tag)

    await ch.basic_consume("agent.metadata", on_message, no_ack=False)
    print("✅ consuming... CTRL+C to stop")
    while True:
        await asyncio.sleep(1)

if __name__ == "__main__":
    asyncio.run(main())
