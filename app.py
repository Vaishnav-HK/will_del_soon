import streamlit as st
import os
import sqlite3
import pandas as pd
import tornado.web
import urllib.parse
import subprocess

# TIER 6: Cloud Deployment Bootstrapper (Auto-install Playwright)
try:
    subprocess.run(["playwright", "install", "chromium"], check=True)
except Exception:
    pass

# ==========================================
# TIER 2: Secure HTTP Headers Injection (Tornado Patch)
# ==========================================
original_set_default_headers = tornado.web.RequestHandler.set_default_headers

def hardened_set_default_headers(self):
    original_set_default_headers(self)
    self.set_header("X-Frame-Options", "DENY")
    self.set_header("Content-Security-Policy", "frame-ancestors 'none';")
    self.set_header("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
    self.set_header("X-Content-Type-Options", "nosniff")

tornado.web.RequestHandler.set_default_headers = hardened_set_default_headers
# ==========================================

import threading
from database.db_manager import init_db, add_asset, get_all_assets
from core.scraper import capture_screenshot

# Initialize Database on Startup
init_db()

st.set_page_config(
    page_title="Next-Gen Security Monitor",
    page_icon="🛡️",
    layout="wide"
)

def run_scraper_bg(url, asset_id):
    """Run the scraper in a background thread"""
    success, msg = capture_screenshot(url, asset_id, is_baseline=True)
    if not success:
        print(f"Failed to capture baseline for asset {asset_id}: {msg}")
        from database.db_manager import update_asset_status
        update_asset_status(asset_id, 'Failed')

import re
import html

def is_valid_url(url):
    regex = re.compile(
        r'^(?:http|https)://' # http:// or https://
        r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+(?:[A-Z]{2,6}\.?|[A-Z0-9-]{2,}\.?)|' # domain
        r'localhost|' # localhost
        r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})' # or ip
        r'(?::\d+)?' # optional port
        r'(?:/?|[/?]\S+)$', re.IGNORECASE)
    return re.match(regex, url) is not None

def render_dashboard():
    st.title("🛡️ Security Dashboard & Asset Management")
    st.markdown("Track and manage your web assets for visual defacement and vulnerabilities.")

    with st.expander("➕ Add New Asset", expanded=True):
        with st.form("add_asset_form", clear_on_submit=True):
            friendly_name = st.text_input("Friendly Name", placeholder="e.g. Production Frontend")
            url = st.text_input("Asset URL", placeholder="https://example.com")
            submitted = st.form_submit_button("Start Monitoring")
            
            if submitted:
                # Tier 1 Input Sanitization
                # Streamlit automatically escapes HTML during rendering, so we just strip whitespace
                # to prevent double-escaping rendering bugs (e.g. &lt;script&gt;)
                safe_name = friendly_name.strip()
                safe_url = url.strip()
                
                if not safe_name or not safe_url:
                    st.error("Both Friendly Name and URL are required.")
                elif not is_valid_url(safe_url):
                    st.error("Invalid URL format. Please ensure it is a valid HTTP/HTTPS address.")
                else:
                    success, msg_or_id = add_asset(safe_url, safe_name)
                    if success:
                        st.success(f"Successfully added '{friendly_name}'. Capturing baseline in background...")
                        
                        assets = get_all_assets()
                        new_asset = next((a for a in assets if a['url'] == url), None)
                        
                        if new_asset:
                            # Start background thread
                            thread = threading.Thread(target=run_scraper_bg, args=(url, new_asset['id']))
                            thread.start()
                            # Removed st.rerun() to keep the success message visible
                    else:
                        st.error(f"Failed to add asset: {msg_or_id}")

    st.subheader("Monitored Assets")
    assets = get_all_assets()
    
    if not assets:
        st.info("No assets currently being monitored. Add one above to get started.")
    else:
        # Create a dataframe for display, styling status column
        df = pd.DataFrame(assets)
        # Reorder and format columns for display
        display_df = df[['id', 'friendly_name', 'url', 'status', 'added_at']]
        display_df.columns = ['ID', 'Asset Name', 'URL', 'Status', 'Date Added']
        
        st.dataframe(
            display_df,
            use_container_width=True,
            hide_index=True
        )
        
        st.markdown("---")
        st.subheader("Manage Assets")
        with st.form("delete_asset_form", clear_on_submit=True):
            asset_options = {a['id']: f"[{a['id']}] {a['friendly_name']} ({a['url']})" for a in assets}
            selected_id = st.selectbox("Select Asset to Delete", options=list(asset_options.keys()), format_func=lambda x: asset_options[x])
            
            if st.form_submit_button("🗑️ Delete Selected Asset", type="primary"):
                from database.db_manager import delete_asset
                delete_asset(selected_id)
                st.success("Asset and its vulnerability history deleted successfully.")
                st.rerun()

def render_visual_monitor():
    st.title("📸 Visual Defacement Monitor")
    st.info("Compare live snapshots against baselines to detect visual defacement.")
    
    import os
    from core.scraper import capture_screenshot
    from core.visual_comparator import run_defacement_check
    
    assets = get_all_assets()
    monitored_assets = [a for a in assets if a['status'] not in ['Pending', 'Failed']]
    
    if not monitored_assets:
        st.warning("No monitored assets available. Please add and baseline an asset first in the Dashboard.")
        return
        
    selected_name = st.selectbox("Select Asset to Monitor", options=[a['friendly_name'] for a in monitored_assets])
    asset = next(a for a in monitored_assets if a['friendly_name'] == selected_name)
    
    st.subheader(f"Monitoring: {asset['url']}")
    
    col1, col2 = st.columns(2)
    baseline_path = os.path.join("storage", "baselines", f"baseline_{asset['id']}.png")
    current_path = os.path.join("storage", "snapshots", f"current_{asset['id']}.png")
    diff_path = os.path.join("storage", "snapshots", f"diff_{asset['id']}.png")
    
    with col1:
        st.markdown("### Baseline")
        if os.path.exists(baseline_path):
            st.image(baseline_path, use_container_width=True)
        else:
            st.error("Baseline image not found.")
            
    with col2:
        st.markdown("### Current Snapshot")
        if os.path.exists(diff_path) and os.path.exists(current_path):
            # Show diff if it exists
            if asset['status'] == 'CRITICAL / DEFACED':
                st.error("🚨 Showing Diff Map")
                st.image(diff_path, caption="Red = Changed Pixels", use_container_width=True)
            else:
                st.image(current_path, use_container_width=True)
        elif os.path.exists(current_path):
            st.image(current_path, use_container_width=True)
        else:
            st.info("No live snapshot captured yet.")
            
    st.markdown("---")
    if st.button("🔍 Capture Live Snapshot & Analyze", type="primary"):
        with st.spinner("Scraping live site and analyzing pixels..."):
            # We run this synchronously in the button press because the user is actively waiting for it
            success, msg = capture_screenshot(asset['url'], asset['id'], is_baseline=False)
            
            if success:
                score, is_defaced, diff_img = run_defacement_check(asset['id'], baseline_path, msg)
                if is_defaced:
                    st.error(f"🚨 CRITICAL DEFACEMENT DETECTED! (Variance: {score:.2f}%)")
                else:
                    st.success(f"✅ Website looks normal. (Variance: {score:.2f}%)")
            else:
                st.error(f"Failed to capture snapshot: {msg}")

def render_vulnerability_scanner():
    st.title("🐛 Vulnerability Scanner")
    st.info("Run lightweight DAST scans and view identified vulnerabilities.")
    
    from database.db_manager import get_vulnerabilities
    from core.scanner import run_dast_scan
    
    assets = get_all_assets()
    monitored_assets = [a for a in assets if a['status'] not in ['Pending', 'Failed']]
    
    if not monitored_assets:
        st.warning("No monitored assets available. Please add and baseline an asset first in the Dashboard.")
        return
        
    selected_name = st.selectbox("Select Asset to Scan", options=[a['friendly_name'] for a in monitored_assets])
    asset = next(a for a in monitored_assets if a['friendly_name'] == selected_name)
    
    col1, col2 = st.columns([3, 1])
    with col1:
        st.subheader(f"Scanning Target: {asset['url']}")
    with col2:
        if st.button("🚀 Run Active Scan", type="primary", use_container_width=True):
            with st.spinner("Injecting payloads and checking headers..."):
                success, result = run_dast_scan(asset['url'], asset['id'])
                if success:
                    st.success(f"Scan complete! Found {len(result)} potential issues.")
                else:
                    st.error(f"Scan failed: {result}")
                    
    st.markdown("---")
    st.subheader("Vulnerability Feed")
    
    vulns = get_vulnerabilities(asset['id'])
    
    if not vulns:
        st.success("🎉 No vulnerabilities found for this asset yet!")
    else:
        # Create visual feed
        for v in vulns:
            # Color coding based on severity
            color = "blue"
            icon = "ℹ️"
            if v['severity'] == "Critical":
                color = "red"
                icon = "🚨"
            elif v['severity'] == "High":
                color = "orange"
                icon = "🔥"
            elif v['severity'] == "Medium":
                color = "yellow"
                icon = "⚠️"
                
            with st.expander(f"{icon} **[{v['severity']}]** {v['vuln_type']} - {v['found_at']}"):
                st.markdown(f"**Description:** {v['description']}")
                
    st.markdown("---")
    st.subheader("🤖 AI Threat Intelligence Advisor")
    st.info("Leverage an LLM to automatically generate an Incident Response brief and prioritized remediation steps.")
    
    if st.button("Generate Executive Threat Brief", type="primary"):
        with st.spinner("Consulting AI Security Analyst..."):
            from services.ai_advisor import ThreatAdvisor
            advisor = ThreatAdvisor()
            report = advisor.analyze_vulnerabilities(asset['url'], vulns)
            
            if "error" in report:
                st.error(f"AI API Error: {report['error']}")
            else:
                with st.chat_message("assistant", avatar="🤖"):
                    st.markdown(f"### Threat Level: `{report.get('threat_level', 'UNKNOWN')}`")
                    st.markdown(f"**Risk Breakdown:**\n\n{report.get('risk_breakdown', '')}")
                    st.markdown("**Remediation Steps:**")
                    for step in report.get('remediation_steps', []):
                        st.markdown(f"- {step}")

import streamlit.components.v1 as components
from dotenv import load_dotenv

load_dotenv()

def check_authentication():
    if st.session_state.get("authenticated", False):
        return True
        
    if "email" in st.query_params:
        st.session_state.authenticated = True
        st.session_state.user_email = st.query_params["email"]
        st.query_params.clear()
        st.rerun()
        return True
        
    st.title("🔒 Enterprise DevSecOps Login")
    st.markdown("Please authenticate with your authorized Google account to access the security platform.")
    
    api_key = os.environ.get("FIREBASE_API_KEY")
    auth_domain = os.environ.get("FIREBASE_AUTH_DOMAIN")
    project_id = os.environ.get("FIREBASE_PROJECT_ID")
    
    if not api_key:
        st.warning("⚠️ Firebase configuration missing from Secrets/.env file.")
        return False
        
    # URL encode the Firebase config so the static HTML can read it
    params = urllib.parse.urlencode({
        "apiKey": api_key,
        "authDomain": auth_domain,
        "projectId": project_id
    })
    
    auth_url = f"app/static/auth.html?{params}"
    
    st.markdown("---")
    st.markdown(f"### 👉 [Click here to Sign In with Google]({auth_url})")
    st.markdown("*(This will securely open the Google OAuth popup via Streamlit Static Serving)*")
    
    return False

def main():
    if not check_authentication():
        return
        
    st.sidebar.title(f"Navigation")
    st.sidebar.caption(f"Logged in as: {st.session_state.user_email}")
    if st.sidebar.button("Log Out"):
        st.session_state.authenticated = False
        st.session_state.user_email = None
        st.rerun()
    page = st.sidebar.radio(
        "Go to",
        ["Dashboard", "Visual Monitor", "Vulnerability Scanner"]
    )

    if page == "Dashboard":
        render_dashboard()
    elif page == "Visual Monitor":
        render_visual_monitor()
    elif page == "Vulnerability Scanner":
        render_vulnerability_scanner()

if __name__ == "__main__":
    main()
