FROM python:3.11-slim
WORKDIR /app
# Copy source files
COPY src/ /app/src/
COPY apify.json /app/
# Install dependencies
RUN pip install --no-cache-dir \
    requests \
    python-dotenv
# Set Python path
ENV PYTHONPATH=/app
# Run main.py
CMD ["python", "-m", "src.main"]
