# 🔥 FIXED: Virtual Environment - NO PIP ROOT WARNING
FROM python:3.11-slim

WORKDIR /app

# ✅ CREATE VIRTUAL ENVIRONMENT (eliminates pip root warning)
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Install dependencies INSIDE venv (no root warning)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy source code
COPY . .

# Default command
CMD ["python", "src/main.py"]
