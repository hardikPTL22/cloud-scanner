FROM python:3.13

WORKDIR /app

COPY requirements.txt ./

RUN pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 5000

CMD ["fastapi", "dev", "app.py", "--port", "5000", "--host", "0.0.0.0"]
