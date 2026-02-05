#!/usr/bin/env python3
"""
Capture HMAC-SHA256 code section from Checklist page.
For PPT requirement: 고위험 명령 HMAC/서명 강제
"""
import asyncio
from pathlib import Path
from playwright.async_api import async_playwright

SCREENSHOTS_DIR = Path(__file__).parent.parent / "docs" / "screenshots"
DASHBOARD_URL = "http://localhost:8501"


async def main():
    print("=" * 60)
    print("Capturing HMAC Code Screenshot")
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

        # Scroll to Code-verifiable section
        print("\n2. Scrolling to Code-Verifiable section...")
        await page.evaluate("window.scrollTo(0, document.body.scrollHeight / 2)")
        await asyncio.sleep(1)

        # Find HMAC expander and click to expand
        print("\n3. Finding and expanding HMAC code section...")
        try:
            # Look for HMAC expander
            hmac_expander = page.locator('div[data-testid="stExpander"]:has-text("HMAC-SHA256")').first
            if await hmac_expander.count() > 0:
                await hmac_expander.click()
                await asyncio.sleep(1)
                await hmac_expander.scroll_into_view_if_needed()
                await asyncio.sleep(0.5)
                await hmac_expander.screenshot(path=SCREENSHOTS_DIR / "14_hmac_algorithm.png")
                print("   -> 14_hmac_algorithm.png (HMAC-SHA256 code section)")
            else:
                print("   HMAC expander not found, trying alternative search...")
                # Try searching for "compute_hmac"
                compute_hmac_expander = page.locator('div[data-testid="stExpander"]:has-text("compute_hmac")').first
                if await compute_hmac_expander.count() > 0:
                    await compute_hmac_expander.click()
                    await asyncio.sleep(1)
                    await compute_hmac_expander.scroll_into_view_if_needed()
                    await asyncio.sleep(0.5)
                    await compute_hmac_expander.screenshot(path=SCREENSHOTS_DIR / "14_hmac_algorithm.png")
                    print("   -> 14_hmac_algorithm.png (compute_hmac code section)")
                else:
                    print("   Could not find HMAC section")
        except Exception as e:
            print(f"   Error: {e}")

        await context.close()
        await browser.close()

    print("\n" + "=" * 60)
    print("Done!")
    print("=" * 60)


if __name__ == "__main__":
    asyncio.run(main())
