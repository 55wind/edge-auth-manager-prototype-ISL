#!/usr/bin/env python3
"""
Capture screenshots for 3-tier architecture (Agent, Gateway, Manager).
"""
import asyncio
from pathlib import Path
from playwright.async_api import async_playwright

SCREENSHOTS_DIR = Path(__file__).parent.parent / "docs" / "screenshots"
DASHBOARD_URL = "http://localhost:8501"


async def main():
    print("=" * 60)
    print("Capturing 3-Tier Architecture Screenshots")
    print("=" * 60)

    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        context = await browser.new_context(viewport={"width": 1920, "height": 1080})
        page = await context.new_page()

        # =====================================================
        # 1. Agent - TLS-secured AMQP connection code
        # =====================================================
        print("\n1. Capturing Agent code section (TLS-secured AMQP)...")
        await page.goto(f"{DASHBOARD_URL}/Checklist")
        await page.wait_for_load_state("networkidle", timeout=15000)
        await asyncio.sleep(3)

        try:
            # Scroll to Code-Verifiable section (Message Bus Security)
            await page.evaluate("window.scrollTo(0, document.body.scrollHeight * 0.7)")
            await asyncio.sleep(1)

            # Find TLS-secured AMQP expander (shows SecurePublisher code)
            amqp_expander = page.locator('div[data-testid="stExpander"]:has-text("TLS-secured AMQP")').first
            if await amqp_expander.count() > 0:
                await amqp_expander.click()
                await asyncio.sleep(1)
                await amqp_expander.scroll_into_view_if_needed()
                await asyncio.sleep(0.5)
                await amqp_expander.screenshot(path=SCREENSHOTS_DIR / "55_agent_amqp_code.png")
                print("   -> 55_agent_amqp_code.png (Agent TLS-secured AMQP)")
            else:
                print("   TLS-secured AMQP expander not found")
        except Exception as e:
            print(f"   Error: {e}")

        # =====================================================
        # 2. Gateway (RabbitMQ) - from RabbitMQ Management
        # =====================================================
        print("\n2. Capturing Gateway (RabbitMQ) section...")
        try:
            # Use RabbitMQ Management UI
            await page.goto("http://localhost:15672/")
            await page.wait_for_load_state("networkidle", timeout=10000)
            await asyncio.sleep(2)

            # Login if needed
            username_input = page.locator('input[name="username"]')
            if await username_input.count() > 0:
                await username_input.fill("isl")
                await page.locator('input[name="password"]').fill("wjdqhqhghdusrntlf1!")
                await page.locator('input[type="submit"]').click()
                await asyncio.sleep(2)

            # Take overview screenshot
            await page.screenshot(path=SCREENSHOTS_DIR / "56_gateway_rabbitmq.png")
            print("   -> 56_gateway_rabbitmq.png (RabbitMQ Overview)")
        except Exception as e:
            print(f"   RabbitMQ error: {e}, using existing screenshot")

        # =====================================================
        # 3. Manager - Overview page
        # =====================================================
        print("\n3. Capturing Manager section...")
        await page.goto(f"{DASHBOARD_URL}/Overview")
        await page.wait_for_load_state("networkidle", timeout=15000)
        await asyncio.sleep(3)

        try:
            await page.screenshot(path=SCREENSHOTS_DIR / "57_manager_overview.png")
            print("   -> 57_manager_overview.png (Manager Overview)")
        except Exception as e:
            print(f"   Error: {e}")

        await context.close()
        await browser.close()

    print("\n" + "=" * 60)
    print("Done!")
    print("=" * 60)


if __name__ == "__main__":
    asyncio.run(main())
