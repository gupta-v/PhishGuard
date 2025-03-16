import sqlite3

DB_PATH = "database/phishing.db"

def init_db():
    """Initialize the database with required tables."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS scan_results (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            url TEXT UNIQUE,
            is_phishing INTEGER,  -- 1 for phishing, 0 for safe
            title TEXT,
            description TEXT,
            scanned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    conn.commit()
    conn.close()

def save_scan_result(url, is_phishing, title, description):
    """Save scan results into the database, replacing outdated entries."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO scan_results (url, is_phishing, title, description, scanned_at)
        VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP)
        ON CONFLICT(url) DO UPDATE SET
            is_phishing = excluded.is_phishing,
            title = excluded.title,
            description = excluded.description,
            scanned_at = CURRENT_TIMESTAMP
    """, (url, int(is_phishing), title, description))
    conn.commit()
    conn.close()

def get_scan_history(limit=10):
    """Retrieve the latest scan results from the database."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
        SELECT url, is_phishing, title, description, scanned_at FROM scan_results
        ORDER BY scanned_at DESC LIMIT ?
    """, (limit,))
    results = cursor.fetchall()
    conn.close()
    return results
