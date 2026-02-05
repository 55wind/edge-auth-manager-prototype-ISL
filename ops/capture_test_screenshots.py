#!/usr/bin/env python3
"""
Capture Test Scenarios page screenshots after running tests.
"""
import asyncio
from pathlib import Path
from playwright.async_api import async_playwright

SCREENSHOTS_DIR = Path(__file__).parent.parent / "docs" / "screenshots"
DASHBOARD_URL = "http://localhost:8501"


async def main():
    print("=" * 60)
    print("Capturing Test Scenarios Screenshots")
    print("=" * 60)

    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        context = await browser.new_context(viewport={"width": 1920, "height": 1080})
        page = await context.new_page()

        # Go to Test Scenarios page
        print("\n1. Opening Test Scenarios page...")
        await page.goto(f"{DASHBOARD_URL}/Test_Scenarios")
        await page.wait_for_load_state("networkidle", timeout=15000)
        await asyncio.sleep(5)

        # Click "Run Single Cycle" button for immediate results
        print("2. Running single test cycle...")
        try:
            single_btn = page.locator('button:has-text("Run Single Cycle")')
            if await single_btn.count() > 0:
                await single_btn.click()
                print("   Clicked 'Run Single Cycle' button")
                print("   Waiting for tests to complete...")
                # Wait for tests to complete - watch for status change
                await asyncio.sleep(60)  # Wait longer for test completion
            else:
                print("   'Run Single Cycle' button not found, trying Start...")
                start_btn = page.locator('button:has-text("Start")')
                if await start_btn.count() > 0:
                    await start_btn.click()
                    print("   Clicked Start button, waiting 60 seconds...")
                    await asyncio.sleep(60)
        except Exception as e:
            print(f"   Button error: {e}")
            await asyncio.sleep(30)

        # Wait for page to update with results
        print("3. Waiting for results to appear...")
        await asyncio.sleep(10)

        # Take screenshot without refresh to preserve state
        print("4. Capturing Current Cycle...")
        await page.screenshot(path=SCREENSHOTS_DIR / "45_test_current_cycle.png", full_page=True)
        await page.screenshot(path=SCREENSHOTS_DIR / "24_test_agent_security.png", full_page=True)
        await page.screenshot(path=SCREENSHOTS_DIR / "08_test_mtls.png", full_page=True)
        await page.screenshot(path=SCREENSHOTS_DIR / "15_test_rbac.png", full_page=True)
        await page.screenshot(path=SCREENSHOTS_DIR / "23_test_messagebus.png", full_page=True)
        await page.screenshot(path=SCREENSHOTS_DIR / "32_test_registration.png", full_page=True)
        await page.screenshot(path=SCREENSHOTS_DIR / "35_test_auth_apis.png", full_page=True)
        await page.screenshot(path=SCREENSHOTS_DIR / "39_test_rmq_health.png", full_page=True)
        await page.screenshot(path=SCREENSHOTS_DIR / "40_test_rmq_permissions.png", full_page=True)
        print("   -> Captured test result screenshots")

        # Click Historical Stats tab
        print("5. Capturing Historical Stats...")
        try:
            hist_tab = page.locator('button[role="tab"]:has-text("Historical")')
            if await hist_tab.count() > 0:
                await hist_tab.click()
                await asyncio.sleep(2)
                await page.screenshot(path=SCREENSHOTS_DIR / "46_test_historical.png", full_page=True)
                print("   -> 46_test_historical.png")
        except Exception as e:
            print(f"   Historical tab error: {e}")

        # Click Category Breakdown tab
        print("6. Capturing Category Breakdown...")
        try:
            cat_tab = page.locator('button[role="tab"]:has-text("Category")')
            if await cat_tab.count() > 0:
                await cat_tab.click()
                await asyncio.sleep(2)
                await page.screenshot(path=SCREENSHOTS_DIR / "47_test_category.png", full_page=True)
                print("   -> 47_test_category.png")
        except Exception as e:
            print(f"   Category tab error: {e}")

        # Click Test Log tab
        print("7. Capturing Test Log...")
        try:
            log_tab = page.locator('button[role="tab"]:has-text("Test Log")')
            if await log_tab.count() > 0:
                await log_tab.click()
                await asyncio.sleep(2)
                await page.screenshot(path=SCREENSHOTS_DIR / "48_test_log.png", full_page=True)
                print("   -> 48_test_log.png")
        except Exception as e:
            print(f"   Test Log tab error: {e}")

        # Click Security Config tab
        print("8. Capturing Security Config...")
        try:
            sec_tab = page.locator('button[role="tab"]:has-text("Security Config")')
            if await sec_tab.count() > 0:
                await sec_tab.click()
                await asyncio.sleep(2)
                await page.screenshot(path=SCREENSHOTS_DIR / "19_security_config.png", full_page=True)
                print("   -> 19_security_config.png")
        except Exception as e:
            print(f"   Security Config tab error: {e}")

        await context.close()
        await browser.close()

    print("\n" + "=" * 60)
    print("Done! Test screenshots recaptured.")
    print("=" * 60)


if __name__ == "__main__":
    asyncio.run(main())
