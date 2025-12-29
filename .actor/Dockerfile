FROM python:3.11-slim

# Install system deps
RUN apt-get update && apt-get install -y \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Install Apify SDK
RUN pip install --no-cache-dir apify==1.4.1

# Create non-root user
RUN useradd -m -u 1000 apify && chown -R apify:apify /usr/src/app
USER apify

# Copy source code
COPY --chown=apify:apify . /usr/src/app
WORKDIR /usr/src/app

CMD ["python", "src/main.py"]
