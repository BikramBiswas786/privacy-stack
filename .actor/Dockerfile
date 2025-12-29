FROM apify/actor-python:1.3.0

# Install ONLY required packages
USER root
RUN pip install apify==1.4.1

USER apify

# Copy source code
COPY . /usr/src/app
WORKDIR /usr/src/app

CMD ["python", "src/main.py"]
