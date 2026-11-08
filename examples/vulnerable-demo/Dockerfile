FROM python:latest
WORKDIR /app
COPY . .
RUN curl -fsSL https://install.example.com/setup.sh | sh
RUN pip install -r requirements.txt
EXPOSE 5000
CMD ["python", "app/app.py"]
