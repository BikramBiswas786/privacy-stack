FROM apify/actor-python:latest

COPY . /usr/src/app
WORKDIR /usr/src/app

USER apify

CMD ["python", "src/main.py"]
