FROM python:3.12-slim
COPY relay.py /relay.py
COPY spool /srv/relay/spool
COPY config /srv/relay/config
EXPOSE 7000
CMD ["python", "/relay.py"]
