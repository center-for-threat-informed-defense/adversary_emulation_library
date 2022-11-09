# Simple DB client to print out VALUEVAULT Data
#
# VALUEVAULT table:
# logins(
#    	 origin_url VARCHAR NOT NULL,
#        username_value VARCHAR,
#        password VARCHAR
#       )

import sqlite3
from pathlib import Path

db_path = f'{Path.home()}\\AppData\\Roaming\\fsociety.dat'
con = sqlite3.connect(db_path)

cur = con.cursor()

print("Logins:")
count = 1
for row in cur.execute('SELECT * FROM logins'):
    print(f'{count}: url="{row[0]}" username="{row[1]}" password="{row[2]}"')
    count = count + 1
