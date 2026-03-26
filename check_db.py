import sqlite3
conn = sqlite3.connect('mortex_cekilis.db')
tables = conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()
print("Tables:", [t[0] for t in tables])
winners_cols = conn.execute("PRAGMA table_info(winners)").fetchall()
print("Winners columns:", [(c[1], c[2]) for c in winners_cols])
conn.close()
