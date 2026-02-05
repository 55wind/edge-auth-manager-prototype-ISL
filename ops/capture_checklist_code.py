#!/usr/bin/env python3
"""
Capture Checklist page code sections - only the expanded section, not full page.
"""
import asyncio
from pathlib import Path
from playwright.async_api import async_playwright

SCREENSHOTS_DIR = Path(__file__).parent.parent / "docs" / "screenshots"
DASHBOARD_URL = "http://localhost:8501"


async def main():
    print("=" * 60)
    print("Capturing Checklist Code Screenshots (Section Only)")
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

        # Capture QoS Retry/Backoff code section (50)
        print("\n2. Capturing QoS Retry/Backoff code section...")
        try:
            retry_expander = page.locator('div[data-testid="stExpander"]:has-text("Retry / exponential backoff with jitter")').first
            if await retry_expander.count() > 0:
                await retry_expander.click()
                await asyncio.sleep(1)
                await retry_expander.scroll_into_view_if_needed()
                await asyncio.sleep(0.5)
                # Screenshot only the expander element
                await retry_expander.screenshot(path=SCREENSHOTS_DIR / "50_checklist_network_code.png")
                print("   -> 50_checklist_network_code.png")
            else:
                print("   Retry expander not found")
        except Exception as e:
            print(f"   Error: {e}")

        # Reload for clean state
        await page.goto(f"{DASHBOARD_URL}/Checklist")
        await page.wait_for_load_state("networkidle", timeout=15000)
        await asyncio.sleep(3)

        # Capture Docker network code section (51)
        print("\n3. Capturing Docker network configuration code section...")
        try:
            docker_expander = page.locator('div[data-testid="stExpander"]:has-text("Docker network segmentation (internal + external)")').first
            if await docker_expander.count() > 0:
                await docker_expander.click()
                await asyncio.sleep(1)
                await docker_expander.scroll_into_view_if_needed()
                await asyncio.sleep(0.5)
                # Screenshot only the expander element
                await docker_expander.screenshot(path=SCREENSHOTS_DIR / "51_checklist_container_code.png")
                print("   -> 51_checklist_container_code.png")
            else:
                print("   Docker expander not found")
        except Exception as e:
            print(f"   Error: {e}")

        # Reload for clean state
        await page.goto(f"{DASHBOARD_URL}/Checklist")
        await page.wait_for_load_state("networkidle", timeout=15000)
        await asyncio.sleep(3)

        # Capture mTLS code section (52)
        print("\n4. Capturing mTLS code section...")
        try:
            mtls_expander = page.locator('div[data-testid="stExpander"]:has-text("mTLS handshake & session")').first
            if await mtls_expander.count() > 0:
                await mtls_expander.click()
                await asyncio.sleep(1)
                await mtls_expander.scroll_into_view_if_needed()
                await asyncio.sleep(0.5)
                # Screenshot only the expander element
                await mtls_expander.screenshot(path=SCREENSHOTS_DIR / "52_checklist_mtls_code.png")
                print("   -> 52_checklist_mtls_code.png")
            else:
                print("   mTLS expander not found")
        except Exception as e:
            print(f"   Error: {e}")

        await context.close()
        await browser.close()

    print("\n" + "=" * 60)
    print("Done!")
    print("=" * 60)


if __name__ == "__main__":
    asyncio.run(main())
