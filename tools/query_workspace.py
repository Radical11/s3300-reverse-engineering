"""Read-only search/address lookup in an unpacked S3300 workspace database."""
import argparse
import json
from pathlib import Path
import sqlite3
from contextlib import closing


def query(database, *, term=None, address=None, limit=50):
    if not 1 <= limit <= 1000:
        raise ValueError("Limit must be 1..1000")
    uri = database.resolve(strict=True).as_uri()+"?mode=ro"
    with closing(sqlite3.connect(uri, uri=True)) as db:
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA query_only=ON")
        if address is not None:
            has_functions = db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='functions'").fetchone()
            return {"address": hex(address),
                    "regions": [dict(r) for r in db.execute("SELECT * FROM regions WHERE virtual_start<=? AND virtual_start+size>?", (address,address))],
                    "symbols": [dict(r) for r in db.execute("SELECT * FROM symbols WHERE value=? OR (size>0 AND value<=? AND value+size>?) LIMIT ?", (address,address,address,limit))],
                    "functions": [dict(r) for r in db.execute("SELECT * FROM functions WHERE start<=? AND end_exclusive>? LIMIT ?", (address,address,limit))] if has_functions else [],
                    "nearby_strings": [dict(r) for r in db.execute("SELECT * FROM code_strings WHERE virtual_address BETWEEN ? AND ? ORDER BY abs(virtual_address-?) LIMIT ?", (address-256,address+256,address,limit))]}
        # Escape SQL wildcard characters so queries remain literal text searches.
        pattern = "%"+term.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")+"%"
        result = {}
        for table, column in (("code_strings","text"), ("ui_strings","text_projection"), ("resources","path"), ("symbols","name")):
            result[table] = [dict(r) for r in db.execute(f"SELECT * FROM {table} WHERE {column} LIKE ? ESCAPE '\\' LIMIT ?", (pattern,limit))]
        return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("database", type=Path)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--search")
    group.add_argument("--address", type=lambda s:int(s,0))
    parser.add_argument("--limit", type=int, default=50)
    args = parser.parse_args()
    print(json.dumps(query(args.database, term=args.search, address=args.address, limit=args.limit), ensure_ascii=True, indent=2))


if __name__ == "__main__":
    main()
