FROM python:3.10

ENV PYTHONUNBUFFERED 1

# Создание и переход в рабочую директорию

WORKDIR /app/

COPY requirements.txt .

RUN pip install --upgrade pip
RUN pip install -r requirements.txt

COPY . .