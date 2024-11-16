FROM python:alpine3.7

WORKDIR /usr/src/app

COPY order.py .
COPY requirements.txt .

RUN pip install --upgrade pip
RUN pip install -r requirements.txt

EXPOSE 3002

ENTRYPOINT [ "python" ]

CMD [ "order.py" ]