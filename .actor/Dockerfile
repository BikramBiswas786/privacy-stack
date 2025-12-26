FROM apify/actor-python:latest

COPY . /usr/src/app
WORKDIR /usr/src/app

RUN echo "CACHE_BUST_$(date +%s)" > /tmp/cache_bust.txt

CMD ["python", "src/main.py"]

