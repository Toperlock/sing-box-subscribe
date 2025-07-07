FROM python:3.11-slim
COPY . /sing-box-subscribe
WORKDIR /sing-box-subscribe
RUN \
    pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt
EXPOSE 5000
CMD ["python", "api/app.py"]