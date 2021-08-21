FROM python:3-alpine

# Add your instructions to dockerize the application
# App must run on port 8000

WORKDIR /auth_api

COPY requirements.txt .

RUN pip install --upgrade pip
RUN pip install -r requirements.txt

COPY auth_api/ .

EXPOSE 8000

CMD [ "python", "./api.py" ]
