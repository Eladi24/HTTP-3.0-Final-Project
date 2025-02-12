FROM python:3.9-slim-bullseye

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    git \
    openssl \
    ca-certificates \
    libssl-dev \
    libffi-dev \
    && rm -rf /var/lib/apt/lists/*

# שדרוג pip למניעת בעיות עם extras
RUN python -m pip install --upgrade pip

# שיבוט הריפו של aioquic
RUN git clone https://github.com/aiortc/aioquic.git /aioquic

# נכנסים לספרייה
WORKDIR /aioquic

# מתקינים aioquic עם חלק מהאקסטרות
RUN pip install --no-cache-dir ".[ws,http3]"
# מתקינים 'wsproto' בכל מקרה
RUN pip install --no-cache-dir wsproto
# מתקינים starlette (נדרש ע"י demo.py)
RUN pip install --no-cache-dir starlette
# אם demo.py מצריך uvicorn או דברים נוספים - נוסיף גם אותם
RUN pip install --no-cache-dir uvicorn

RUN pip install --no-cache-dir Jinja2

# הגדרת PYTHONPATH כדי שיוכל לזהות את תיקיית examples/ כולל demo
ENV PYTHONPATH="/aioquic/examples:${PYTHONPATH}"

# יוצרים תעודה חתומה עצמית
RUN openssl req -x509 -newkey rsa:2048 -nodes \
    -keyout ssl_key.pem -out ssl_cert.pem \
    -subj "/CN=172.17.0.2" -days 365

# חושפים פורט 4433 ב-UDP (וגם TCP אם רוצים)
EXPOSE 4433/udp
EXPOSE 4433/tcp

# אם אתה רוצה להפעיל את demo, ומעוניין ב-WebSocket מתוך demo, 
# פרמטרי http3_server.py יכללו "--websocket=demo.websocket"
CMD ["python", "examples/http3_server.py", \
     "--certificate", "ssl_cert.pem", \
     "--private-key", "ssl_key.pem", \
     "--host", "0.0.0.0", \
     "--port", "4433"]
