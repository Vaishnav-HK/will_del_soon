import sqlite3
import os
from datetime import datetime

DB_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'storage', 'db')
DB_PATH = os.path.join(DB_DIR, 'database.db')

def init_db():
    if not os.path.exists(DB_DIR):
        os.makedirs(DB_DIR)
        
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS assets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            url TEXT UNIQUE,
            friendly_name TEXT,
            added_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            status TEXT DEFAULT 'Pending'
        )
    ''')
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS vulnerabilities (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            asset_id INTEGER,
            severity TEXT,
            vuln_type TEXT,
            description TEXT,
            found_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (asset_id) REFERENCES assets (id)
        )
    ''')
    
    conn.commit()
    conn.close()

def add_asset(url, friendly_name):
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO assets (url, friendly_name) VALUES (?, ?)",
            (url, friendly_name)
        )
        conn.commit()
        return True, "Asset added successfully."
    except sqlite3.IntegrityError:
        return False, "Asset URL already exists."
    except Exception as e:
        return False, str(e)
    finally:
        if 'conn' in locals():
            conn.close()

def get_all_assets():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM assets ORDER BY added_at DESC")
    rows = cursor.fetchall()
    conn.close()
    return [dict(row) for row in rows]

def update_asset_status(asset_id, status):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute(
        "UPDATE assets SET status = ? WHERE id = ?",
        (status, asset_id)
    )
    conn.commit()
    conn.close()

def add_vulnerability(asset_id, severity, vuln_type, description):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO vulnerabilities (asset_id, severity, vuln_type, description) VALUES (?, ?, ?, ?)",
        (asset_id, severity, vuln_type, description)
    )
    conn.commit()
    conn.close()

def get_vulnerabilities(asset_id=None):
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    if asset_id:
        cursor.execute("SELECT * FROM vulnerabilities WHERE asset_id = ? ORDER BY severity DESC, found_at DESC", (asset_id,))
    else:
        cursor.execute("SELECT * FROM vulnerabilities ORDER BY severity DESC, found_at DESC")
    rows = cursor.fetchall()
    conn.close()
    return [dict(row) for row in rows]

def clear_vulnerabilities(asset_id):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("DELETE FROM vulnerabilities WHERE asset_id = ?", (asset_id,))
    conn.commit()
    conn.close()

def delete_asset(asset_id):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("DELETE FROM vulnerabilities WHERE asset_id = ?", (asset_id,))
    cursor.execute("DELETE FROM assets WHERE id = ?", (asset_id,))
    conn.commit()
    conn.close()

