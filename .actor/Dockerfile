FROM apify/actor-python:1

# Install Apify SDK
USER apify
RUN pip install --no-cache-dir apify==1.4.1

# Copy source code
COPY . /usr/src/app
WORKDIR /usr/src/app

CMD python src/main.py
