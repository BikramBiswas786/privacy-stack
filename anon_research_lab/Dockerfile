FROM python:3.11-slim
WORKDIR /app
# Copy Python source files
COPY src/ /app/src/
# Install dependencies
RUN pip install --no-cache-dir \
    requests \
    python-dotenv
# Set Python path
ENV PYTHONPATH=/app
ENV PYTHONUNBUFFERED=1
# Run the main script
CMD ["python", "-m", "src.main"]
