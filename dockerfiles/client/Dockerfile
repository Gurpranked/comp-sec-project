FROM python:3.11-slim

RUN pip install python-gnupg pyyaml

RUN mkdir /app && mkdir /app/gpg_home
ENV GNUPGHOME=/app/gpg_home

COPY client.py /app/client.py
WORKDIR /app

CMD ["python", "client.py"]

