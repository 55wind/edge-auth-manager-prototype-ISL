#!/usr/bin/env python3
"""
Capture theft response (탈취 대응) screenshot from Checklist page.
Shows JWT secret rotation code implementation.
"""
import asyncio
from pathlib import Path
from playwright.async_api import async_playwright

SCREENSHOTS_DIR = Path(__file__).parent.parent / "docs" / "screenshots"
DASHBOARD_URL = "http://localhost:8501"


async def main():
    print("=" * 60)
    print("Capturing Theft Response Screenshot (탈취 대응)")
    print("=" * 60)

    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        context = await browser.new_context(viewport={"width": 1920, "height": 1080})
        page = await context.new_page()

        # Go to Checklist page
        print("\n1. Opening Checklist page...")
        await page.goto(f"{DASHBOARD_URL}/Checklist")
        await page.wait_for_load_state("networkidle", timeout=15000)
        await asyncio.sleep(3)

        # Find JWT secret rotation code section
        print("\n2. Capturing JWT secret rotation code (탈취 대응)...")
        try:
            # Look for JWT rotation or secret rotation expander
            rotation_expander = page.locator('div[data-testid="stExpander"]:has-text("JWT secret rotation")').first
            if await rotation_expander.count() == 0:
                rotation_expander = page.locator('div[data-testid="stExpander"]:has-text("Key rotation")').first
            if await rotation_expander.count() == 0:
                rotation_expander = page.locator('div[data-testid="stExpander"]:has-text("rotation resilience")').first

            if await rotation_expander.count() > 0:
                await rotation_expander.click()
                await asyncio.sleep(1)
                await rotation_expander.scroll_into_view_if_needed()
                await asyncio.sleep(0.5)
                await rotation_expander.screenshot(path=SCREENSHOTS_DIR / "18_last_rotation.png")
                print("   -> 18_last_rotation.png (JWT rotation code)")
            else:
                print("   JWT rotation expander not found, trying alternative...")
                # Try AMQP reconnect which is related to key rotation resilience
                amqp_expander = page.locator('div[data-testid="stExpander"]:has-text("AMQP reconnect")').first
                if await amqp_expander.count() > 0:
                    await amqp_expander.click()
                    await asyncio.sleep(1)
                    await amqp_expander.scroll_into_view_if_needed()
                    await asyncio.sleep(0.5)
                    await amqp_expander.screenshot(path=SCREENSHOTS_DIR / "18_last_rotation.png")
                    print("   -> 18_last_rotation.png (AMQP reconnect for key rotation)")
                else:
                    print("   No suitable expander found")
        except Exception as e:
            print(f"   Error: {e}")

        await context.close()
        await browser.close()

    print("\n" + "=" * 60)
    print("Done!")
    print("=" * 60)


if __name__ == "__main__":
    asyncio.run(main())
