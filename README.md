# certport
checks certstream for CDN, API, S3, Dev, FTP, cloud, archive, db, content, dl, and Sql, confirms if a connection can be made, then returns corresponding color. Then checks for open ports using shodan and returns them *REQUIRES SHODAN KEY*

Installation:  
pip3 install dnspython certstream shodan

Change api_key to your shodan key

Usage:  
python3 certport.py

OR if you'd like to save what you find to files named after each port

python3 certports.py
