#!/usr/bin/env python3
"""
Automated screenshot capture for Edge Auth Manager Dashboard presentation.
Version 2 - with proper waits and RabbitMQ login handling.
"""
import asyncio
import os
from pathlib import Path
from playwright.async_api import async_playwright

# Output directory
SCREENSHOTS_DIR = Path(__file__).parent.parent / "docs" / "screenshots"
SCREENSHOTS_DIR.mkdir(parents=True, exist_ok=True)

# URLs
DASHBOARD_URL = "http://localhost:8501"
RABBITMQ_URL = "http://localhost:15672"
RABBITMQ_USER = "isl"
RABBITMQ_PASS = "wjdqhqhghdusrntlf1!"


async def wait_for_streamlit(page, timeout=15000):
    """Wait for Streamlit to finish loading."""
    try:
        await page.wait_for_load_state("networkidle", timeout=timeout)
        await asyncio.sleep(3)
    except Exception:
        await asyncio.sleep(5)


async def capture_dashboard_screenshots(browser):
    """Capture all dashboard screenshots."""
    context = await browser.new_context(viewport={"width": 1920, "height": 1080})
    page = await context.new_page()

    print("\n=== Capturing Dashboard Screenshots ===\n")

    # 1. Home page
    print("1. Home page...")
    await page.goto(DASHBOARD_URL)
    await wait_for_streamlit(page)
    await page.screenshot(path=SCREENSHOTS_DIR / "42_home_page.png", full_page=True)

    # 2. Overview page
    print("2. Overview page...")
    await page.goto(f"{DASHBOARD_URL}/Overview")
    await wait_for_streamlit(page)
    await page.screenshot(path=SCREENSHOTS_DIR / "07_network_overview.png", full_page=True)
    await page.screenshot(path=SCREENSHOTS_DIR / "20_overview_metrics.png", full_page=True)
    await page.screenshot(path=SCREENSHOTS_DIR / "29_system_health.png", full_page=True)

    # 3. Devices page
    print("3. Devices page...")
    await page.goto(f"{DASHBOARD_URL}/Devices")
    await wait_for_streamlit(page)
    await page.screenshot(path=SCREENSHOTS_DIR / "01_namespace_device_list.png", full_page=True)
    await page.screenshot(path=SCREENSHOTS_DIR / "30_device_registration.png", full_page=True)
    await page.screenshot(path=SCREENSHOTS_DIR / "31_device_lastseen.png", full_page=True)

    # Filter PENDING
    try:
        await page.locator('div[data-testid="stSelectbox"]').first.click()
        await asyncio.sleep(0.5)
        await page.locator('li:has-text("PENDING")').click()
        await asyncio.sleep(1)
        await page.screenshot(path=SCREENSHOTS_DIR / "02_status_pending.png", full_page=True)
    except:
        pass

    # Reset to All
    await page.goto(f"{DASHBOARD_URL}/Devices")
    await wait_for_streamlit(page)
    await page.screenshot(path=SCREENSHOTS_DIR / "05_admin_actions.png", full_page=True)
    await page.screenshot(path=SCREENSHOTS_DIR / "33_cert_actions.png", full_page=True)
    await page.screenshot(path=SCREENSHOTS_DIR / "16_crl_section.png", full_page=True)
    await page.screenshot(path=SCREENSHOTS_DIR / "17_cert_status.png", full_page=True)

    # 4. Authentication page
    print("4. Authentication page...")
    await page.goto(f"{DASHBOARD_URL}/Authentication")
    await wait_for_streamlit(page)
    await page.screenshot(path=SCREENSHOTS_DIR / "10_jwt_security_status.png", full_page=True)
    await page.screenshot(path=SCREENSHOTS_DIR / "11_auth_summary.png", full_page=True)
    await page.screenshot(path=SCREENSHOTS_DIR / "12_token_events.png", full_page=True)
    await page.screenshot(path=SCREENSHOTS_DIR / "14_hmac_algorithm.png", full_page=True)
    await page.screenshot(path=SCREENSHOTS_DIR / "18_last_rotation.png", full_page=True)
    await page.screenshot(path=SCREENSHOTS_DIR / "25_auth_events_timeline.png", full_page=True)
    await page.screenshot(path=SCREENSHOTS_DIR / "36_auth_failure_analysis.png", full_page=True)

    # Expand RBAC
    try:
        await page.locator('text=RBAC Permission Matrix').click()
        await asyncio.sleep(1)
    except:
        pass
    await page.screenshot(path=SCREENSHOTS_DIR / "13_rbac_matrix.png", full_page=True)

    # 5. Security page
    print("5. Security page...")
    await page.goto(f"{DASHBOARD_URL}/Security")
    await wait_for_streamlit(page)
    await page.screenshot(path=SCREENSHOTS_DIR / "26_security_incidents.png", full_page=True)

    # 6. Logs page
    print("6. Logs page...")
    await page.goto(f"{DASHBOARD_URL}/Logs")
    await wait_for_streamlit(page)
    await page.screenshot(path=SCREENSHOTS_DIR / "27_logs_page.png", full_page=True)
    await page.screenshot(path=SCREENSHOTS_DIR / "28_logs_filter.png", full_page=True)

    # 7. Checklist page
    print("7. Checklist page...")
    await page.goto(f"{DASHBOARD_URL}/Checklist")
    await wait_for_streamlit(page)
    await page.screenshot(path=SCREENSHOTS_DIR / "43_checklist_dashboard.png", full_page=True)
    await page.evaluate("window.scrollTo(0, 1500)")
    await asyncio.sleep(1)
    await page.screenshot(path=SCREENSHOTS_DIR / "44_checklist_code.png", full_page=True)

    # 8. Test Scenarios - Start testing and wait
    print("8. Test Scenarios page (waiting for test cycle)...")
    await page.goto(f"{DASHBOARD_URL}/Test_Scenarios")
    await wait_for_streamlit(page)

    # Click Start if available
    try:
        start_btn = page.locator('button:has-text("Start")')
        if await start_btn.count() > 0:
            await start_btn.click()
            print("   Started testing, waiting 40 seconds...")
            await asyncio.sleep(40)  # Wait for test cycle
            await page.reload()
            await wait_for_streamlit(page)
    except:
        pass

    await page.screenshot(path=SCREENSHOTS_DIR / "45_test_current_cycle.png", full_page=True)
    await page.screenshot(path=SCREENSHOTS_DIR / "24_test_agent_security.png", full_page=True)
    await page.screenshot(path=SCREENSHOTS_DIR / "08_test_mtls.png", full_page=True)
    await page.screenshot(path=SCREENSHOTS_DIR / "15_test_rbac.png", full_page=True)
    await page.screenshot(path=SCREENSHOTS_DIR / "23_test_messagebus.png", full_page=True)
    await page.screenshot(path=SCREENSHOTS_DIR / "32_test_registration.png", full_page=True)
    await page.screenshot(path=SCREENSHOTS_DIR / "35_test_auth_apis.png", full_page=True)
    await page.screenshot(path=SCREENSHOTS_DIR / "39_test_rmq_health.png", full_page=True)
    await page.screenshot(path=SCREENSHOTS_DIR / "40_test_rmq_permissions.png", full_page=True)

    # Click tabs
    try:
        await page.locator('button[role="tab"]:has-text("Historical")').click()
        await asyncio.sleep(1)
        await page.screenshot(path=SCREENSHOTS_DIR / "46_test_historical.png", full_page=True)

        await page.locator('button[role="tab"]:has-text("Category")').click()
        await asyncio.sleep(1)
        await page.screenshot(path=SCREENSHOTS_DIR / "47_test_category.png", full_page=True)

        await page.locator('button[role="tab"]:has-text("Test Log")').click()
        await asyncio.sleep(1)
        await page.screenshot(path=SCREENSHOTS_DIR / "48_test_log.png", full_page=True)

        await page.locator('button[role="tab"]:has-text("Security Config")').click()
        await asyncio.sleep(1)
        await page.screenshot(path=SCREENSHOTS_DIR / "19_security_config.png", full_page=True)
    except Exception as e:
        print(f"   Tab error: {e}")

    await context.close()


async def capture_rabbitmq_screenshots(browser):
    """Capture RabbitMQ management UI screenshots with login."""
    context = await browser.new_context(viewport={"width": 1920, "height": 1080})
    page = await context.new_page()

    print("\n=== Capturing RabbitMQ Screenshots ===\n")

    # Login
    print("1. Logging into RabbitMQ...")
    await page.goto(RABBITMQ_URL)
    await asyncio.sleep(2)

    # Fill login form
    try:
        await page.fill('input[name="username"]', RABBITMQ_USER)
        await page.fill('input[name="password"]', RABBITMQ_PASS)
        await page.click('input[type="submit"]')
        await asyncio.sleep(3)
    except Exception as e:
        print(f"   Login error: {e}")

    # Overview
    print("2. RabbitMQ Overview...")
    await page.screenshot(path=SCREENSHOTS_DIR / "22_rabbitmq_overview.png", full_page=True)

    # Connections
    print("3. RabbitMQ Connections...")
    await page.goto(f"{RABBITMQ_URL}/#/connections")
    await asyncio.sleep(2)
    await page.screenshot(path=SCREENSHOTS_DIR / "09_rabbitmq_connections.png", full_page=True)
    await page.screenshot(path=SCREENSHOTS_DIR / "37_rabbitmq_tls.png", full_page=True)

    # Queues
    print("4. RabbitMQ Queues...")
    await page.goto(f"{RABBITMQ_URL}/#/queues")
    await asyncio.sleep(2)
    await page.screenshot(path=SCREENSHOTS_DIR / "21_rabbitmq_queues.png", full_page=True)

    # Queue detail
    try:
        await page.click('a:has-text("agent.metadata")')
        await asyncio.sleep(2)
        await page.screenshot(path=SCREENSHOTS_DIR / "38_queue_metadata.png", full_page=True)
    except:
        pass

    await context.close()


async def main():
    print("=" * 60)
    print("Edge Auth Manager - Screenshot Capture v2")
    print("=" * 60)
    print(f"\nOutput: {SCREENSHOTS_DIR}")

    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        try:
            await capture_dashboard_screenshots(browser)
            await capture_rabbitmq_screenshots(browser)
        finally:
            await browser.close()

    screenshots = list(SCREENSHOTS_DIR.glob("*.png"))
    print(f"\n{'=' * 60}")
    print(f"Done! {len(screenshots)} screenshots saved.")
    print("=" * 60)


if __name__ == "__main__":
    asyncio.run(main())
