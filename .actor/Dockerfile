FROM apify/actor-python:0.5.1

COPY . /usr/src/app
WORKDIR /usr/src/app

USER apify

RUN pip install --no-cache-dir apify-client

CMD ["python", "src/main.py"]
