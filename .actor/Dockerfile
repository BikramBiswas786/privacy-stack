FROM python:3.11-slim

WORKDIR /app

# Create virtual environment (fixes pip warning)
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Copy requirements.txt
COPY requirements.txt .

# Install dependencies using venv pip (NO root warning)
RUN /opt/venv/bin/pip install --upgrade pip && \
    /opt/venv/bin/pip install --no-cache-dir apify-client

# Copy source code
COPY . .

# Run using venv python
CMD ["/opt/venv/bin/python", "src/main.py"]

