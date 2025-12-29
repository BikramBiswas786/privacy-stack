FROM apify/actor-python:0.1.2
COPY . /usr/src/app/
WORKDIR /usr/src/app/
RUN pip install apify-client
CMD ["python", "-m", "src.main"]
