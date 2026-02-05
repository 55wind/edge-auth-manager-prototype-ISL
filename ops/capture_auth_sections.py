#!/usr/bin/env python3
"""
Capture specific sections of Authentication page for different requirements.
"""
import asyncio
from pathlib import Path
from playwright.async_api import async_playwright

SCREENSHOTS_DIR = Path(__file__).parent.parent / "docs" / "screenshots"
DASHBOARD_URL = "http://localhost:8501"


async def main():
    print("=" * 60)
    print("Capturing Authentication Page Sections")
    print("=" * 60)

    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        context = await browser.new_context(viewport={"width": 1920, "height": 1080})
        page = await context.new_page()

        # =====================================================
        # 1. JWT Security Status (TTL/스코프 정의) - 페이지 하단
        # =====================================================
        print("\n1. Capturing JWT Security Status (TTL/스코프 정의)...")
        await page.goto(f"{DASHBOARD_URL}/Authentication")
        await page.wait_for_load_state("networkidle", timeout=15000)
        await asyncio.sleep(3)

        try:
            # Scroll to JWT Security Status section at bottom
            await page.evaluate("window.scrollTo(0, document.body.scrollHeight)")
            await asyncio.sleep(2)

            # Find JWT Security Status section
            jwt_header = page.locator('text=JWT Security Status').first
            if await jwt_header.count() > 0:
                await jwt_header.scroll_into_view_if_needed()
                await asyncio.sleep(1)

            # Take screenshot of current viewport (should show JWT Security Status)
            await page.screenshot(path=SCREENSHOTS_DIR / "10_jwt_security_status.png")
            print("   -> 10_jwt_security_status.png (JWT Security Status section)")
        except Exception as e:
            print(f"   Error: {e}")

        # =====================================================
        # 2. Events by Type (만료 대응 - TOKEN_ISSUED 이벤트)
        # =====================================================
        print("\n2. Capturing Events by Type (만료 대응)...")
        await page.goto(f"{DASHBOARD_URL}/Authentication")
        await page.wait_for_load_state("networkidle", timeout=15000)
        await asyncio.sleep(3)

        try:
            # Find Events by Type section (middle of page)
            events_header = page.locator('text=Events by Type').first
            if await events_header.count() > 0:
                await events_header.scroll_into_view_if_needed()
                await asyncio.sleep(1)
                await page.screenshot(path=SCREENSHOTS_DIR / "12_token_events.png")
                print("   -> 12_token_events.png (Events by Type section)")
            else:
                print("   Events by Type section not found")
        except Exception as e:
            print(f"   Error: {e}")

        # =====================================================
        # 3. Last Rotation + Blocked Tokens (탈취 대응)
        # =====================================================
        print("\n3. Capturing Last Rotation info (탈취 대응)...")
        await page.goto(f"{DASHBOARD_URL}/Authentication")
        await page.wait_for_load_state("networkidle", timeout=15000)
        await asyncio.sleep(3)

        try:
            # Scroll to very bottom for rotation info
            await page.evaluate("window.scrollTo(0, document.body.scrollHeight)")
            await asyncio.sleep(2)

            # Look for "Last JWT secret rotation" text or RBAC section
            rotation_text = page.locator('text=rotation').first
            if await rotation_text.count() > 0:
                await rotation_text.scroll_into_view_if_needed()
                await asyncio.sleep(1)

            await page.screenshot(path=SCREENSHOTS_DIR / "18_last_rotation.png")
            print("   -> 18_last_rotation.png (Rotation info at bottom)")
        except Exception as e:
            print(f"   Error: {e}")

        # =====================================================
        # 4. RBAC Permission Matrix (확장해서 캡처)
        # =====================================================
        print("\n4. Capturing RBAC Permission Matrix...")
        await page.goto(f"{DASHBOARD_URL}/Authentication")
        await page.wait_for_load_state("networkidle", timeout=15000)
        await asyncio.sleep(3)

        try:
            # Scroll to bottom first
            await page.evaluate("window.scrollTo(0, document.body.scrollHeight)")
            await asyncio.sleep(2)

            # Find and click RBAC expander
            rbac_expander = page.locator('div[data-testid="stExpander"]:has-text("RBAC")').first
            if await rbac_expander.count() > 0:
                await rbac_expander.click()
                await asyncio.sleep(1)
                await rbac_expander.scroll_into_view_if_needed()
                await asyncio.sleep(0.5)
                await rbac_expander.screenshot(path=SCREENSHOTS_DIR / "13_rbac_matrix.png")
                print("   -> 13_rbac_matrix.png (RBAC section expanded)")
            else:
                print("   RBAC expander not found")
        except Exception as e:
            print(f"   Error: {e}")

        # =====================================================
        # 5. Failure Analysis (실패 분석)
        # =====================================================
        print("\n5. Capturing Failure Analysis...")
        await page.goto(f"{DASHBOARD_URL}/Authentication")
        await page.wait_for_load_state("networkidle", timeout=15000)
        await asyncio.sleep(3)

        try:
            # Find Failure Analysis section
            failure_header = page.locator('text=Failure Analysis').first
            if await failure_header.count() > 0:
                await failure_header.scroll_into_view_if_needed()
                await asyncio.sleep(1)
                await page.screenshot(path=SCREENSHOTS_DIR / "36_auth_failure_analysis.png")
                print("   -> 36_auth_failure_analysis.png (Failure Analysis section)")
        except Exception as e:
            print(f"   Error: {e}")

        await context.close()
        await browser.close()

    print("\n" + "=" * 60)
    print("Done!")
    print("=" * 60)


if __name__ == "__main__":
    asyncio.run(main())
