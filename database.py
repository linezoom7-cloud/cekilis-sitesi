"""
database.py - SQLite database schema and helper functions for Mortex Çekiliş
"""

import sqlite3
import os

DB_PATH = os.path.join(os.path.dirname(__file__), "mortex_cekilis.db")


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def init_db():
    conn = get_db()
    cur = conn.cursor()
    cur.executescript("""
        CREATE TABLE IF NOT EXISTS settings (
            key   TEXT PRIMARY KEY,
            value TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS raffles (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            name        TEXT    NOT NULL,
            draw_date   TEXT    NOT NULL,
            status      TEXT    NOT NULL DEFAULT 'active'
                        CHECK(status IN ('active', 'drawn', 'cancelled')),
            created_at  TEXT    NOT NULL DEFAULT (datetime('now'))
        );

        CREATE TABLE IF NOT EXISTS entries (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            raffle_id   INTEGER NOT NULL REFERENCES raffles(id) ON DELETE CASCADE,
            full_name   TEXT    NOT NULL,
            contact     TEXT    NOT NULL DEFAULT '',
            tickets     INTEGER NOT NULL DEFAULT 1 CHECK(tickets >= 1),
            added_at    TEXT    NOT NULL DEFAULT (datetime('now'))
        );

        CREATE TABLE IF NOT EXISTS winners (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            raffle_id   INTEGER NOT NULL REFERENCES raffles(id) ON DELETE CASCADE,
            entry_id    INTEGER NOT NULL REFERENCES entries(id),
            rank        INTEGER NOT NULL DEFAULT 1,
            drawn_at    TEXT    NOT NULL DEFAULT (datetime('now'))
        );
    """)
    # Seed default credentials if not set
    cur.execute("INSERT OR IGNORE INTO settings VALUES ('admin_username', 'admin')")
    cur.execute("INSERT OR IGNORE INTO settings VALUES ('admin_password', 'mortex2024')")
    conn.commit()
    conn.close()


# ── Settings ────────────────────────────────────────────────────────────────

def get_setting(key: str, default=None):
    conn = get_db()
    row = conn.execute("SELECT value FROM settings WHERE key = ?", (key,)).fetchone()
    conn.close()
    return row["value"] if row else default


def set_setting(key: str, value: str):
    conn = get_db()
    conn.execute("INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)", (key, value))
    conn.commit()
    conn.close()


# ── Raffles ─────────────────────────────────────────────────────────────────

def get_all_raffles():
    conn = get_db()
    rows = conn.execute(
        "SELECT *, (SELECT COUNT(*) FROM entries WHERE raffle_id = raffles.id) AS participant_count "
        "FROM raffles ORDER BY id DESC"
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_raffle(raffle_id: int):
    conn = get_db()
    row = conn.execute("SELECT * FROM raffles WHERE id = ?", (raffle_id,)).fetchone()
    conn.close()
    return dict(row) if row else None


def create_raffle(name: str, draw_date: str):
    conn = get_db()
    cur = conn.execute("INSERT INTO raffles (name, draw_date) VALUES (?, ?)", (name, draw_date))
    new_id = cur.lastrowid
    conn.commit()
    conn.close()
    return new_id


def delete_raffle(raffle_id: int):
    conn = get_db()
    conn.execute("DELETE FROM winners WHERE raffle_id = ?", (raffle_id,))
    conn.execute("DELETE FROM entries WHERE raffle_id = ?", (raffle_id,))
    conn.execute("DELETE FROM raffles WHERE id = ?", (raffle_id,))
    conn.commit()
    conn.close()


def reset_raffle(raffle_id: int):
    """Delete all winners and restore raffle to active status."""
    conn = get_db()
    conn.execute("DELETE FROM winners WHERE raffle_id = ?", (raffle_id,))
    conn.execute("UPDATE raffles SET status = 'active' WHERE id = ?", (raffle_id,))
    conn.commit()
    conn.close()


def copy_raffle(raffle_id: int, new_name: str, new_date: str, copy_entries: bool = True):
    """Duplicate a raffle (and optionally its entries) returning the new raffle id."""
    conn = get_db()
    cur = conn.execute(
        "INSERT INTO raffles (name, draw_date) VALUES (?, ?)", (new_name, new_date)
    )
    new_id = cur.lastrowid
    if copy_entries:
        entries = conn.execute(
            "SELECT full_name, contact, tickets FROM entries WHERE raffle_id = ?", (raffle_id,)
        ).fetchall()
        conn.executemany(
            "INSERT INTO entries (raffle_id, full_name, contact, tickets) VALUES (?, ?, ?, ?)",
            [(new_id, e["full_name"], e["contact"], e["tickets"]) for e in entries]
        )
    conn.commit()
    conn.close()
    return new_id


# ── Entries ─────────────────────────────────────────────────────────────────

def get_entries_for_raffle(raffle_id: int):
    conn = get_db()
    rows = conn.execute(
        "SELECT * FROM entries WHERE raffle_id = ? ORDER BY id ASC", (raffle_id,)
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def add_entry(raffle_id: int, full_name: str, contact: str, tickets: int):
    conn = get_db()
    cur = conn.execute(
        "INSERT INTO entries (raffle_id, full_name, contact, tickets) VALUES (?, ?, ?, ?)",
        (raffle_id, full_name, contact, tickets),
    )
    new_id = cur.lastrowid
    conn.commit()
    conn.close()
    return new_id


def bulk_add_entries(raffle_id: int, rows):
    """rows: list of (full_name, tickets) tuples."""
    conn = get_db()
    conn.executemany(
        "INSERT INTO entries (raffle_id, full_name, contact, tickets) VALUES (?, ?, '', ?)",
        [(raffle_id, r[0], r[1]) for r in rows]
    )
    conn.commit()
    conn.close()


def delete_entry(entry_id: int):
    conn = get_db()
    conn.execute("DELETE FROM entries WHERE id = ?", (entry_id,))
    conn.commit()
    conn.close()


# ── Winners ─────────────────────────────────────────────────────────────────

def get_winners_for_raffle(raffle_id: int):
    conn = get_db()
    rows = conn.execute(
        """SELECT w.id, w.rank, w.drawn_at, e.full_name, e.contact, e.tickets
           FROM winners w JOIN entries e ON e.id = w.entry_id
           WHERE w.raffle_id = ? ORDER BY w.rank ASC""",
        (raffle_id,),
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_all_winners():
    """Return all winners across all raffles for the history page."""
    conn = get_db()
    rows = conn.execute(
        """SELECT w.id, w.rank, w.drawn_at, e.full_name, e.tickets,
                  r.id AS raffle_id, r.name AS raffle_name, r.draw_date
           FROM winners w
           JOIN entries e ON e.id = w.entry_id
           JOIN raffles r ON r.id = w.raffle_id
           ORDER BY w.drawn_at DESC"""
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def save_winners(raffle_id: int, entry_ids: list):
    """Save multiple winners with rank ordering."""
    conn = get_db()
    for rank, entry_id in enumerate(entry_ids, start=1):
        conn.execute(
            "INSERT INTO winners (raffle_id, entry_id, rank) VALUES (?, ?, ?)",
            (raffle_id, entry_id, rank)
        )
    conn.execute("UPDATE raffles SET status = 'drawn' WHERE id = ?", (raffle_id,))
    conn.commit()
    conn.close()
