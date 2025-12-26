FROM apify/actor-python

WORKDIR /usr/src/app

# Copy requirements and install
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

# Copy source code
COPY src ./src

# Ensure unbuffered output
ENV PYTHONUNBUFFERED=1

# Run the actor
CMD ["python", "-m", "src.main"]
