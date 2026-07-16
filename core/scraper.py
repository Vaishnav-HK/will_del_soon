import os
import sys
import asyncio
from playwright.sync_api import sync_playwright
from database.db_manager import update_asset_status

STORAGE_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'storage')
BASELINES_DIR = os.path.join(STORAGE_DIR, 'baselines')
SNAPSHOTS_DIR = os.path.join(STORAGE_DIR, 'snapshots')

# Ensure directories exist
os.makedirs(BASELINES_DIR, exist_ok=True)
os.makedirs(SNAPSHOTS_DIR, exist_ok=True)

def capture_screenshot(url, asset_id, is_baseline=True):
    """
    Connect to a target URL, wait for stable load, and capture a full-page screenshot.
    Returns (success_boolean, message_or_filepath)
    """
    try:
        # TIER 3: SSRF Protection
        if url.lower().startswith("file://"):
            return False, "SSRF Blocked: Local file protocol access is explicitly forbidden."
            
        if sys.platform == 'win32':
            asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())
            
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
            
        with sync_playwright() as p:
            # TIER 3: Playwright Sandbox Isolation
            browser = p.chromium.launch(
                headless=True,
                args=["--no-sandbox", "--disable-setuid-sandbox"]
            )
            
            context = browser.new_context(viewport={'width': 1280, 'height': 1024})
            context.set_default_timeout(15000) # TIER 3: Strict 15s global timeout
            
            page = context.new_page()
            
            # TIER 3: Network Intercept - forcefully abort any dynamic local file access
            page.route("**/*", lambda route: route.abort() if route.request.url.startswith("file://") else route.continue_())
            
            # Navigate and wait until network is mostly idle or timeout
            page.goto(url, wait_until='networkidle', timeout=15000)
            
            # Wait a little bit more just for any dynamic animations to settle
            page.wait_for_timeout(2000)
            
            file_name = f"{'baseline' if is_baseline else 'current'}_{asset_id}.png"
            dir_path = BASELINES_DIR if is_baseline else SNAPSHOTS_DIR
            file_path = os.path.join(dir_path, file_name)
            
            page.screenshot(path=file_path, full_page=True)
            browser.close()
            
            if is_baseline:
                update_asset_status(asset_id, 'Monitored')
                
            return True, file_path
            
    except Exception as e:
        return False, str(e)
