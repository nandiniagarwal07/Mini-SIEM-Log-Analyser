import sqlite3

DATABASE = "database/siem.db"


def create_database():

    conn = sqlite3.connect(DATABASE)

    cursor = conn.cursor()

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS log_analysis (

        id INTEGER PRIMARY KEY AUTOINCREMENT,

        total_logs INTEGER,

        alerts INTEGER,

        high INTEGER,

        medium INTEGER,

        low INTEGER

    )
    """)

    conn.commit()
    conn.close()


def save_analysis(total_logs, alerts, high, medium, low):

    conn = sqlite3.connect(DATABASE)

    cursor = conn.cursor()

    cursor.execute("""
    INSERT INTO log_analysis
    (total_logs, alerts, high, medium, low)

    VALUES (?, ?, ?, ?, ?)
    """, (total_logs, alerts, high, medium, low))

    conn.commit()
    conn.close()

def show_database():
    print("show_database() called")

    conn = sqlite3.connect(DATABASE)

    cursor = conn.cursor()

    cursor.execute("SELECT * FROM log_analysis")

    rows = cursor.fetchall()

    print("\nDATABASE CONTENT")

    for row in rows:
        print(row)

    conn.close()