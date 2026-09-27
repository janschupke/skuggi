FROM python:3.12-slim
WORKDIR /opt/app
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt
COPY app.py NOTES.txt ./
EXPOSE 5000
CMD ["python", "app.py"]
