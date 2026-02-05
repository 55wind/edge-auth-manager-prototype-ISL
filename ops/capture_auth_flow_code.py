#!/usr/bin/env python3
"""
Capture authentication/data flow code sections from Checklist page.
For section 1-7: 인증·데이터 흐름 시퀀스 설계
"""
import asyncio
from pathlib import Path
from playwright.async_api import async_playwright

SCREENSHOTS_DIR = Path(__file__).parent.parent / "docs" / "screenshots"
DASHBOARD_URL = "http://localhost:8501"


async def main():
    print("=" * 60)
    print("Capturing Auth Flow Code Screenshots")
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

        # =====================================================
        # 1. Device Registration code (Boot → Register)
        # =====================================================
        print("\n2. Capturing Device Registration code...")
        try:
            await page.evaluate("window.scrollTo(0, document.body.scrollHeight * 0.5)")
            await asyncio.sleep(1)

            # Find registration/retry expander
            reg_expander = page.locator('div[data-testid="stExpander"]:has-text("Retry / exponential backoff")').first
            if await reg_expander.count() > 0:
                await reg_expander.click()
                await asyncio.sleep(1)
                await reg_expander.scroll_into_view_if_needed()
                await asyncio.sleep(0.5)
                await reg_expander.screenshot(path=SCREENSHOTS_DIR / "58_register_retry_code.png")
                print("   -> 58_register_retry_code.png (Registration with retry/backoff)")
            else:
                print("   Registration expander not found")
        except Exception as e:
            print(f"   Error: {e}")

        # =====================================================
        # 2. Token Refresh code (Auth → Token Refresh)
        # =====================================================
        print("\n3. Capturing Token Refresh code...")
        await page.goto(f"{DASHBOARD_URL}/Checklist")
        await page.wait_for_load_state("networkidle", timeout=15000)
        await asyncio.sleep(3)

        try:
            await page.evaluate("window.scrollTo(0, document.body.scrollHeight * 0.4)")
            await asyncio.sleep(1)

            # Find JWT issuance expander
            jwt_expander = page.locator('div[data-testid="stExpander"]:has-text("JWT issuance")').first
            if await jwt_expander.count() > 0:
                await jwt_expander.click()
                await asyncio.sleep(1)
                await jwt_expander.scroll_into_view_if_needed()
                await asyncio.sleep(0.5)
                await jwt_expander.screenshot(path=SCREENSHOTS_DIR / "59_jwt_token_code.png")
                print("   -> 59_jwt_token_code.png (JWT token issuance)")
            else:
                print("   JWT expander not found")
        except Exception as e:
            print(f"   Error: {e}")

        # =====================================================
        # 3. Buffer/Reconnect code (Connection Drop Exception)
        # =====================================================
        print("\n4. Capturing Buffer/Reconnect code...")
        await page.goto(f"{DASHBOARD_URL}/Checklist")
        await page.wait_for_load_state("networkidle", timeout=15000)
        await asyncio.sleep(3)

        try:
            await page.evaluate("window.scrollTo(0, document.body.scrollHeight * 0.7)")
            await asyncio.sleep(1)

            # Find local buffer expander
            buffer_expander = page.locator('div[data-testid="stExpander"]:has-text("Local buffer")').first
            if await buffer_expander.count() > 0:
                await buffer_expander.click()
                await asyncio.sleep(1)
                await buffer_expander.scroll_into_view_if_needed()
                await asyncio.sleep(0.5)
                await buffer_expander.screenshot(path=SCREENSHOTS_DIR / "60_buffer_reconnect_code.png")
                print("   -> 60_buffer_reconnect_code.png (Local buffer for disconnection)")
            else:
                print("   Buffer expander not found, trying Key rotation resilience...")
                key_expander = page.locator('div[data-testid="stExpander"]:has-text("Key rotation resilience")').first
                if await key_expander.count() > 0:
                    await key_expander.click()
                    await asyncio.sleep(1)
                    await key_expander.screenshot(path=SCREENSHOTS_DIR / "60_buffer_reconnect_code.png")
                    print("   -> 60_buffer_reconnect_code.png (Key rotation resilience)")
        except Exception as e:
            print(f"   Error: {e}")

        await context.close()
        await browser.close()

    print("\n" + "=" * 60)
    print("Done!")
    print("=" * 60)


if __name__ == "__main__":
    asyncio.run(main())
