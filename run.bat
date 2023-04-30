call .\venv\Scripts\activate.bat
mitmdump --showhost --script ./main.py --listen-host 0.0.0.0 --listen-port 8080 --ssl-insecure
