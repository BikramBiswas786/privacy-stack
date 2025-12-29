FROM python:3.11-slim
WORKDIR /app
RUN apt-get update && apt-get install -y git curl && rm -rf /var/lib/apt/lists/*
RUN pip install requests
COPY . /usr/src/app/
WORKDIR /usr/src/app/
CMD ["python", "-m", "src.main"]
