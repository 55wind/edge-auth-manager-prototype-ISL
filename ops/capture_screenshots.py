#!/usr/bin/env python3
"""
Automated screenshot capture for Edge Auth Manager Dashboard presentation.
Uses Playwright to capture all required screenshots.
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


async def wait_for_streamlit(page, timeout=10000):
    """Wait for Streamlit to finish loading."""
    try:
        # Wait for the main content to load
        await page.wait_for_load_state("networkidle", timeout=timeout)
        await asyncio.sleep(2)  # Extra wait for Streamlit rendering
    except Exception:
        await asyncio.sleep(3)


async def capture_dashboard_screenshots(browser):
    """Capture all dashboard screenshots."""
    context = await browser.new_context(viewport={"width": 1920, "height": 1080})
    page = await context.new_page()

    print("\n=== Capturing Dashboard Screenshots ===\n")

    # 1. Home page
    print("1. Capturing Home page...")
    await page.goto(DASHBOARD_URL)
    await wait_for_streamlit(page)
    await page.screenshot(path=SCREENSHOTS_DIR / "42_home_page.png", full_page=True)
    print("   -> 42_home_page.png")

    # 2. Overview page
    print("2. Capturing Overview page...")
    await page.goto(f"{DASHBOARD_URL}/Overview")
    await wait_for_streamlit(page)
    await page.screenshot(path=SCREENSHOTS_DIR / "20_overview_metrics.png", full_page=True)
    print("   -> 20_overview_metrics.png")

    # Also capture Security Posture section
    await page.screenshot(path=SCREENSHOTS_DIR / "07_network_overview.png", full_page=True)
    print("   -> 07_network_overview.png")

    # System Health
    await page.screenshot(path=SCREENSHOTS_DIR / "29_system_health.png", full_page=True)
    print("   -> 29_system_health.png")

    # 3. Devices page
    print("3. Capturing Devices page...")
    await page.goto(f"{DASHBOARD_URL}/Devices")
    await wait_for_streamlit(page)
    await page.screenshot(path=SCREENSHOTS_DIR / "01_namespace_device_list.png", full_page=True)
    print("   -> 01_namespace_device_list.png")

    # Device list with agent details
    await page.screenshot(path=SCREENSHOTS_DIR / "30_device_registration.png", full_page=True)
    print("   -> 30_device_registration.png")

    # Last seen
    await page.screenshot(path=SCREENSHOTS_DIR / "31_device_lastseen.png", full_page=True)
    print("   -> 31_device_lastseen.png")

    # Try to filter by status - PENDING
    try:
        status_select = page.locator('div[data-testid="stSelectbox"]').first
        if await status_select.count() > 0:
            await status_select.click()
            await asyncio.sleep(0.5)
            pending_option = page.locator('li:has-text("PENDING")')
            if await pending_option.count() > 0:
                await pending_option.click()
                await asyncio.sleep(1)
                await page.screenshot(path=SCREENSHOTS_DIR / "02_status_pending.png", full_page=True)
                print("   -> 02_status_pending.png")
    except Exception as e:
        print(f"   (Could not filter PENDING: {e})")

    # Reset and capture Admin Actions
    await page.goto(f"{DASHBOARD_URL}/Devices")
    await wait_for_streamlit(page)
    await page.screenshot(path=SCREENSHOTS_DIR / "05_admin_actions.png", full_page=True)
    print("   -> 05_admin_actions.png")

    # Cert actions
    await page.screenshot(path=SCREENSHOTS_DIR / "33_cert_actions.png", full_page=True)
    print("   -> 33_cert_actions.png")

    # Certificate Status section
    await page.screenshot(path=SCREENSHOTS_DIR / "17_cert_status.png", full_page=True)
    print("   -> 17_cert_status.png")

    # CRL section
    await page.screenshot(path=SCREENSHOTS_DIR / "16_crl_section.png", full_page=True)
    print("   -> 16_crl_section.png")

    # 4. Authentication page
    print("4. Capturing Authentication page...")
    await page.goto(f"{DASHBOARD_URL}/Authentication")
    await wait_for_streamlit(page)
    await page.screenshot(path=SCREENSHOTS_DIR / "11_auth_summary.png", full_page=True)
    print("   -> 11_auth_summary.png")

    # JWT Security Status
    await page.screenshot(path=SCREENSHOTS_DIR / "10_jwt_security_status.png", full_page=True)
    print("   -> 10_jwt_security_status.png")

    # HMAC Algorithm
    await page.screenshot(path=SCREENSHOTS_DIR / "14_hmac_algorithm.png", full_page=True)
    print("   -> 14_hmac_algorithm.png")

    # Auth events chart
    await page.screenshot(path=SCREENSHOTS_DIR / "25_auth_events_timeline.png", full_page=True)
    print("   -> 25_auth_events_timeline.png")

    # Events by type
    await page.screenshot(path=SCREENSHOTS_DIR / "12_token_events.png", full_page=True)
    print("   -> 12_token_events.png")

    # Last rotation
    await page.screenshot(path=SCREENSHOTS_DIR / "18_last_rotation.png", full_page=True)
    print("   -> 18_last_rotation.png")

    # Failure analysis
    await page.screenshot(path=SCREENSHOTS_DIR / "36_auth_failure_analysis.png", full_page=True)
    print("   -> 36_auth_failure_analysis.png")

    # Try to expand RBAC matrix
    try:
        rbac_expander = page.locator('div[data-testid="stExpander"]:has-text("RBAC")')
        if await rbac_expander.count() > 0:
            await rbac_expander.click()
            await asyncio.sleep(1)
            await page.screenshot(path=SCREENSHOTS_DIR / "13_rbac_matrix.png", full_page=True)
            print("   -> 13_rbac_matrix.png")
    except Exception as e:
        print(f"   (Could not expand RBAC: {e})")
        await page.screenshot(path=SCREENSHOTS_DIR / "13_rbac_matrix.png", full_page=True)

    # 5. Security page
    print("5. Capturing Security page...")
    await page.goto(f"{DASHBOARD_URL}/Security")
    await wait_for_streamlit(page)
    await page.screenshot(path=SCREENSHOTS_DIR / "26_security_incidents.png", full_page=True)
    print("   -> 26_security_incidents.png")

    # 6. Logs page
    print("6. Capturing Logs page...")
    await page.goto(f"{DASHBOARD_URL}/Logs")
    await wait_for_streamlit(page)
    await page.screenshot(path=SCREENSHOTS_DIR / "27_logs_page.png", full_page=True)
    print("   -> 27_logs_page.png")

    # Logs filter
    await page.screenshot(path=SCREENSHOTS_DIR / "28_logs_filter.png", full_page=True)
    print("   -> 28_logs_filter.png")

    # 7. Checklist page
    print("7. Capturing Checklist page...")
    await page.goto(f"{DASHBOARD_URL}/Checklist")
    await wait_for_streamlit(page)
    await page.screenshot(path=SCREENSHOTS_DIR / "43_checklist_dashboard.png", full_page=True)
    print("   -> 43_checklist_dashboard.png")

    # Try to scroll down for code-verifiable section
    await page.evaluate("window.scrollTo(0, document.body.scrollHeight / 2)")
    await asyncio.sleep(1)
    await page.screenshot(path=SCREENSHOTS_DIR / "44_checklist_code.png", full_page=True)
    print("   -> 44_checklist_code.png")

    # 8. Test Scenarios page
    print("8. Capturing Test Scenarios page...")
    await page.goto(f"{DASHBOARD_URL}/Test_Scenarios")
    await wait_for_streamlit(page)

    # Start testing if not already running
    try:
        start_btn = page.locator('button:has-text("Start")')
        if await start_btn.count() > 0:
            await start_btn.click()
            print("   Starting continuous testing...")
            await asyncio.sleep(35)  # Wait for one test cycle
    except Exception:
        pass

    # Current Cycle tab
    await page.screenshot(path=SCREENSHOTS_DIR / "45_test_current_cycle.png", full_page=True)
    print("   -> 45_test_current_cycle.png")

    # Agent Security tests
    await page.screenshot(path=SCREENSHOTS_DIR / "24_test_agent_security.png", full_page=True)
    print("   -> 24_test_agent_security.png")

    # mTLS tests
    await page.screenshot(path=SCREENSHOTS_DIR / "08_test_mtls.png", full_page=True)
    print("   -> 08_test_mtls.png")

    # Auth API tests
    await page.screenshot(path=SCREENSHOTS_DIR / "35_test_auth_apis.png", full_page=True)
    print("   -> 35_test_auth_apis.png")

    # RBAC tests
    await page.screenshot(path=SCREENSHOTS_DIR / "15_test_rbac.png", full_page=True)
    print("   -> 15_test_rbac.png")

    # Message bus tests
    await page.screenshot(path=SCREENSHOTS_DIR / "23_test_messagebus.png", full_page=True)
    print("   -> 23_test_messagebus.png")

    # Registration tests
    await page.screenshot(path=SCREENSHOTS_DIR / "32_test_registration.png", full_page=True)
    print("   -> 32_test_registration.png")

    # RabbitMQ health test
    await page.screenshot(path=SCREENSHOTS_DIR / "39_test_rmq_health.png", full_page=True)
    print("   -> 39_test_rmq_health.png")

    # RabbitMQ permissions test
    await page.screenshot(path=SCREENSHOTS_DIR / "40_test_rmq_permissions.png", full_page=True)
    print("   -> 40_test_rmq_permissions.png")

    # Try to click on tabs
    try:
        # Historical Stats tab
        hist_tab = page.locator('button:has-text("Historical")')
        if await hist_tab.count() > 0:
            await hist_tab.click()
            await asyncio.sleep(1)
            await page.screenshot(path=SCREENSHOTS_DIR / "46_test_historical.png", full_page=True)
            print("   -> 46_test_historical.png")

        # Category Breakdown tab
        cat_tab = page.locator('button:has-text("Category")')
        if await cat_tab.count() > 0:
            await cat_tab.click()
            await asyncio.sleep(1)
            await page.screenshot(path=SCREENSHOTS_DIR / "47_test_category.png", full_page=True)
            print("   -> 47_test_category.png")

        # Test Log tab
        log_tab = page.locator('button:has-text("Test Log")')
        if await log_tab.count() > 0:
            await log_tab.click()
            await asyncio.sleep(1)
            await page.screenshot(path=SCREENSHOTS_DIR / "48_test_log.png", full_page=True)
            print("   -> 48_test_log.png")

        # Security Config tab
        sec_tab = page.locator('button:has-text("Security Config")')
        if await sec_tab.count() > 0:
            await sec_tab.click()
            await asyncio.sleep(1)
            await page.screenshot(path=SCREENSHOTS_DIR / "19_security_config.png", full_page=True)
            print("   -> 19_security_config.png")
    except Exception as e:
        print(f"   (Tab navigation issue: {e})")

    await context.close()


async def capture_rabbitmq_screenshots(browser):
    """Capture RabbitMQ management UI screenshots."""
    context = await browser.new_context(
        viewport={"width": 1920, "height": 1080},
        http_credentials={"username": RABBITMQ_USER, "password": RABBITMQ_PASS}
    )
    page = await context.new_page()

    print("\n=== Capturing RabbitMQ Screenshots ===\n")

    # Overview
    print("1. Capturing RabbitMQ Overview...")
    await page.goto(f"{RABBITMQ_URL}/#/")
    await asyncio.sleep(3)
    await page.screenshot(path=SCREENSHOTS_DIR / "22_rabbitmq_overview.png", full_page=True)
    print("   -> 22_rabbitmq_overview.png")

    # Connections
    print("2. Capturing RabbitMQ Connections...")
    await page.goto(f"{RABBITMQ_URL}/#/connections")
    await asyncio.sleep(2)
    await page.screenshot(path=SCREENSHOTS_DIR / "09_rabbitmq_connections.png", full_page=True)
    print("   -> 09_rabbitmq_connections.png")

    # TLS connection
    await page.screenshot(path=SCREENSHOTS_DIR / "37_rabbitmq_tls.png", full_page=True)
    print("   -> 37_rabbitmq_tls.png")

    # Queues
    print("3. Capturing RabbitMQ Queues...")
    await page.goto(f"{RABBITMQ_URL}/#/queues")
    await asyncio.sleep(2)
    await page.screenshot(path=SCREENSHOTS_DIR / "21_rabbitmq_queues.png", full_page=True)
    print("   -> 21_rabbitmq_queues.png")

    # Queue detail
    try:
        queue_link = page.locator('a:has-text("agent.metadata")')
        if await queue_link.count() > 0:
            await queue_link.click()
            await asyncio.sleep(2)
            await page.screenshot(path=SCREENSHOTS_DIR / "38_queue_metadata.png", full_page=True)
            print("   -> 38_queue_metadata.png")
    except Exception:
        pass

    await context.close()


async def main():
    """Main entry point."""
    print("=" * 60)
    print("Edge Auth Manager - Automated Screenshot Capture")
    print("=" * 60)
    print(f"\nOutput directory: {SCREENSHOTS_DIR}")

    async with async_playwright() as p:
        print("\nLaunching browser...")
        browser = await p.chromium.launch(headless=True)

        try:
            await capture_dashboard_screenshots(browser)
            await capture_rabbitmq_screenshots(browser)
        finally:
            await browser.close()

    # Count screenshots
    screenshots = list(SCREENSHOTS_DIR.glob("*.png"))
    print("\n" + "=" * 60)
    print(f"Capture complete! {len(screenshots)} screenshots saved.")
    print(f"Location: {SCREENSHOTS_DIR}")
    print("=" * 60)


if __name__ == "__main__":
    asyncio.run(main())
