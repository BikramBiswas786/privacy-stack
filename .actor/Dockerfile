FROM python:3.11-slim
RUN pip install apify-client
COPY . /usr/src/app/
WORKDIR /usr/src/app/
CMD ["python", "-m", "src.main"]
