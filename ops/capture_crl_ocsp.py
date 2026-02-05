#!/usr/bin/env python3
"""
Capture CRL/OCSP section from Authentication page.
"""
import asyncio
from pathlib import Path
from playwright.async_api import async_playwright

SCREENSHOTS_DIR = Path(__file__).parent.parent / "docs" / "screenshots"
DASHBOARD_URL = "http://localhost:8501"


async def main():
    print("=" * 60)
    print("Capturing CRL/OCSP Section")
    print("=" * 60)

    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        context = await browser.new_context(viewport={"width": 1920, "height": 1080})
        page = await context.new_page()

        # Go to Authentication page
        print("\n1. Opening Authentication page...")
        await page.goto(f"{DASHBOARD_URL}/Authentication")
        await page.wait_for_load_state("networkidle", timeout=15000)
        await asyncio.sleep(3)

        # Scroll to CRL/OCSP section at very bottom
        print("\n2. Scrolling to CRL/OCSP section...")
        await page.evaluate("window.scrollTo(0, document.body.scrollHeight)")
        await asyncio.sleep(2)

        # Find CRL/OCSP section
        try:
            crl_header = page.locator('text=Certificate Revocation Check').first
            if await crl_header.count() > 0:
                await crl_header.scroll_into_view_if_needed()
                await asyncio.sleep(1)

                # Take screenshot of the section
                await page.screenshot(path=SCREENSHOTS_DIR / "54_crl_ocsp_section.png")
                print("   -> 54_crl_ocsp_section.png (CRL/OCSP section)")
            else:
                print("   CRL/OCSP section header not found, taking bottom screenshot...")
                await page.screenshot(path=SCREENSHOTS_DIR / "54_crl_ocsp_section.png")
                print("   -> 54_crl_ocsp_section.png (bottom of page)")
        except Exception as e:
            print(f"   Error: {e}")

        await context.close()
        await browser.close()

    print("\n" + "=" * 60)
    print("Done!")
    print("=" * 60)


if __name__ == "__main__":
    asyncio.run(main())
