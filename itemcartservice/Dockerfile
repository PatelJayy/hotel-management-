FROM python:3.11.6-alpine3.18

WORKDIR /usr/src/app

COPY item.py .
COPY requirements.txt .

RUN pip install --upgrade pip
RUN pip install -r requirements.txt

EXPOSE 3001

ENTRYPOINT [ "python" ]

CMD [ "item.py" ]