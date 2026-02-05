#!/usr/bin/env python3
"""
Capture PKI-related sections for section 1-5 of PPT.
1. Root/Intermediate CA hierarchy
2. CRL section
3. JWT Secret Rotation
"""
import asyncio
from pathlib import Path
from playwright.async_api import async_playwright

SCREENSHOTS_DIR = Path(__file__).parent.parent / "docs" / "screenshots"
DASHBOARD_URL = "http://localhost:8501"


async def main():
    print("=" * 60)
    print("Capturing PKI Sections for Section 1-5")
    print("=" * 60)

    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        context = await browser.new_context(viewport={"width": 1920, "height": 1080})
        page = await context.new_page()

        # =====================================================
        # 1. Intermediate CA code (Root/Intermediate CA 연동)
        # =====================================================
        print("\n1. Capturing Intermediate CA code (루트/중간 CA 연동)...")
        await page.goto(f"{DASHBOARD_URL}/Checklist")
        await page.wait_for_load_state("networkidle", timeout=15000)
        await asyncio.sleep(3)

        try:
            # Scroll to Code-Verifiable section
            await page.evaluate("window.scrollTo(0, document.body.scrollHeight * 0.7)")
            await asyncio.sleep(1)

            # Find Intermediate CA expander
            ca_expander = page.locator('div[data-testid="stExpander"]:has-text("Intermediate CA")').first
            if await ca_expander.count() > 0:
                await ca_expander.click()
                await asyncio.sleep(1)
                await ca_expander.scroll_into_view_if_needed()
                await asyncio.sleep(0.5)
                await ca_expander.screenshot(path=SCREENSHOTS_DIR / "53_intermediate_ca_code.png")
                print("   -> 53_intermediate_ca_code.png (Intermediate CA hierarchy code)")
            else:
                print("   Intermediate CA expander not found")
        except Exception as e:
            print(f"   Error: {e}")

        # =====================================================
        # 2. CRL Section from Devices page
        # =====================================================
        print("\n2. Capturing CRL Section (CRL/OCSP)...")
        await page.goto(f"{DASHBOARD_URL}/Devices")
        await page.wait_for_load_state("networkidle", timeout=15000)
        await asyncio.sleep(3)

        try:
            # Scroll to bottom for CRL section
            await page.evaluate("window.scrollTo(0, document.body.scrollHeight)")
            await asyncio.sleep(2)

            # Find CRL expander or section
            crl_section = page.locator('text=Certificate Revocation List').first
            if await crl_section.count() > 0:
                await crl_section.scroll_into_view_if_needed()
                await asyncio.sleep(1)
                await page.screenshot(path=SCREENSHOTS_DIR / "16_crl_section.png")
                print("   -> 16_crl_section.png (CRL section)")
            else:
                # Try expander
                crl_expander = page.locator('div[data-testid="stExpander"]:has-text("CRL")').first
                if await crl_expander.count() > 0:
                    await crl_expander.click()
                    await asyncio.sleep(1)
                    await crl_expander.screenshot(path=SCREENSHOTS_DIR / "16_crl_section.png")
                    print("   -> 16_crl_section.png (CRL expander)")
                else:
                    print("   CRL section not found")
        except Exception as e:
            print(f"   Error: {e}")

        # =====================================================
        # 3. JWT Secret Rotation from Authentication page
        # =====================================================
        print("\n3. Capturing JWT Secret Rotation (무중단 로테이션)...")
        await page.goto(f"{DASHBOARD_URL}/Authentication")
        await page.wait_for_load_state("networkidle", timeout=15000)
        await asyncio.sleep(3)

        try:
            # Scroll to JWT Security Status at bottom
            await page.evaluate("window.scrollTo(0, document.body.scrollHeight)")
            await asyncio.sleep(2)

            # Find rotation info
            jwt_header = page.locator('text=JWT Security Status').first
            if await jwt_header.count() > 0:
                await jwt_header.scroll_into_view_if_needed()
                await asyncio.sleep(1)
                await page.screenshot(path=SCREENSHOTS_DIR / "18_last_rotation.png")
                print("   -> 18_last_rotation.png (JWT rotation info)")
        except Exception as e:
            print(f"   Error: {e}")

        # =====================================================
        # 4. Security Config (overall PKI config)
        # =====================================================
        print("\n4. Capturing Security Config overview...")
        await page.goto(f"{DASHBOARD_URL}/Overview")
        await page.wait_for_load_state("networkidle", timeout=15000)
        await asyncio.sleep(3)

        try:
            # Find Security Posture section
            security_section = page.locator('text=Security Posture').first
            if await security_section.count() > 0:
                await security_section.scroll_into_view_if_needed()
                await asyncio.sleep(1)
                await page.screenshot(path=SCREENSHOTS_DIR / "19_security_config.png")
                print("   -> 19_security_config.png (Security config)")
        except Exception as e:
            print(f"   Error: {e}")

        await context.close()
        await browser.close()

    print("\n" + "=" * 60)
    print("Done!")
    print("=" * 60)


if __name__ == "__main__":
    asyncio.run(main())
