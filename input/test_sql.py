# Another SQL-focused sample to trigger heuristics
user = "admin"
name = user
sql = f"SELECT id FROM accounts WHERE name = '{name}'"
# usage without params
try:
    cursor.execute(sql)
except Exception:
    pass
