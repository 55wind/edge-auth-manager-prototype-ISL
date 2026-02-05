#!/usr/bin/env python3
"""
Capture the full auth flow code from Checklist page.
Boot → Register → Approve → Auth → Authorization → Data Exchange
"""
import asyncio
from pathlib import Path
from playwright.async_api import async_playwright

SCREENSHOTS_DIR = Path(__file__).parent.parent / "docs" / "screenshots"
DASHBOARD_URL = "http://localhost:8501"


async def main():
    print("=" * 60)
    print("Capturing Full Auth Flow Code Screenshot")
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

        # Find the agent main loop code which shows full flow
        print("\n2. Capturing Agent main loop (full flow)...")
        try:
            await page.evaluate("window.scrollTo(0, document.body.scrollHeight * 0.5)")
            await asyncio.sleep(1)

            # Find async event loop expander - this shows the full flow
            loop_expander = page.locator('div[data-testid="stExpander"]:has-text("Async event loop")').first
            if await loop_expander.count() > 0:
                await loop_expander.click()
                await asyncio.sleep(1)
                await loop_expander.scroll_into_view_if_needed()
                await asyncio.sleep(0.5)
                await loop_expander.screenshot(path=SCREENSHOTS_DIR / "61_full_auth_flow_code.png")
                print("   -> 61_full_auth_flow_code.png (Full auth flow - agent main loop)")
            else:
                print("   Async event loop not found, trying alternative...")
                # Try device discovery which also shows the flow
                discovery_expander = page.locator('div[data-testid="stExpander"]:has-text("Device discovery")').first
                if await discovery_expander.count() > 0:
                    await discovery_expander.click()
                    await asyncio.sleep(1)
                    await discovery_expander.screenshot(path=SCREENSHOTS_DIR / "61_full_auth_flow_code.png")
                    print("   -> 61_full_auth_flow_code.png (Device discovery)")
        except Exception as e:
            print(f"   Error: {e}")

        await context.close()
        await browser.close()

    print("\n" + "=" * 60)
    print("Done!")
    print("=" * 60)


if __name__ == "__main__":
    asyncio.run(main())
