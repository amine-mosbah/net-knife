FROM python:3.12-slim
WORKDIR /opt/netknife
COPY . /opt/netknife
RUN pip install --no-cache-dir -r requirements.txt
ENTRYPOINT ["python", "cli/netknife.py"]

