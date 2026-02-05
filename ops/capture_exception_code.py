#!/usr/bin/env python3
"""
Capture exception handling code screenshots from Checklist page.
1. Token expiration auto-refresh
2. Duplicate registration handling
3. Connection drop handling
"""
import asyncio
from pathlib import Path
from playwright.async_api import async_playwright

SCREENSHOTS_DIR = Path(__file__).parent.parent / "docs" / "screenshots"
DASHBOARD_URL = "http://localhost:8501"


async def main():
    print("=" * 60)
    print("Capturing Exception Handling Code Screenshots")
    print("=" * 60)

    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        context = await browser.new_context(viewport={"width": 1920, "height": 1080})
        page = await context.new_page()

        # =====================================================
        # 1. Token expiration auto-refresh
        # =====================================================
        print("\n1. Capturing Token expiration code...")
        await page.goto(f"{DASHBOARD_URL}/Checklist")
        await page.wait_for_load_state("networkidle", timeout=15000)
        await asyncio.sleep(3)

        try:
            # Scroll to Exception Handling section (near bottom)
            await page.evaluate("window.scrollTo(0, document.body.scrollHeight * 0.9)")
            await asyncio.sleep(1)

            # Find Token expiration expander
            token_expander = page.locator('div[data-testid="stExpander"]:has-text("Token expiration auto-refresh")').first
            if await token_expander.count() > 0:
                await token_expander.click()
                await asyncio.sleep(1)
                await token_expander.scroll_into_view_if_needed()
                await asyncio.sleep(0.5)
                await token_expander.screenshot(path=SCREENSHOTS_DIR / "64_token_expiration_code.png")
                print("   -> 64_token_expiration_code.png")
            else:
                print("   Token expiration expander not found")
        except Exception as e:
            print(f"   Error: {e}")

        # =====================================================
        # 2. Duplicate registration handling
        # =====================================================
        print("\n2. Capturing Duplicate registration code...")
        await page.goto(f"{DASHBOARD_URL}/Checklist")
        await page.wait_for_load_state("networkidle", timeout=15000)
        await asyncio.sleep(3)

        try:
            await page.evaluate("window.scrollTo(0, document.body.scrollHeight * 0.9)")
            await asyncio.sleep(1)

            # Find Duplicate registration expander
            dup_expander = page.locator('div[data-testid="stExpander"]:has-text("Duplicate registration handling")').first
            if await dup_expander.count() > 0:
                await dup_expander.click()
                await asyncio.sleep(1)
                await dup_expander.scroll_into_view_if_needed()
                await asyncio.sleep(0.5)
                await dup_expander.screenshot(path=SCREENSHOTS_DIR / "65_duplicate_registration_code.png")
                print("   -> 65_duplicate_registration_code.png")
            else:
                print("   Duplicate registration expander not found")
        except Exception as e:
            print(f"   Error: {e}")

        # =====================================================
        # 3. Connection drop handling
        # =====================================================
        print("\n3. Capturing Connection drop code...")
        await page.goto(f"{DASHBOARD_URL}/Checklist")
        await page.wait_for_load_state("networkidle", timeout=15000)
        await asyncio.sleep(3)

        try:
            await page.evaluate("window.scrollTo(0, document.body.scrollHeight * 0.95)")
            await asyncio.sleep(1)

            # Find Connection drop expander
            conn_expander = page.locator('div[data-testid="stExpander"]:has-text("Connection drop handling")').first
            if await conn_expander.count() > 0:
                await conn_expander.click()
                await asyncio.sleep(1)
                await conn_expander.scroll_into_view_if_needed()
                await asyncio.sleep(0.5)
                await conn_expander.screenshot(path=SCREENSHOTS_DIR / "66_connection_drop_code.png")
                print("   -> 66_connection_drop_code.png")
            else:
                print("   Connection drop expander not found")
        except Exception as e:
            print(f"   Error: {e}")

        await context.close()
        await browser.close()

    print("\n" + "=" * 60)
    print("Done!")
    print("=" * 60)


if __name__ == "__main__":
    asyncio.run(main())
