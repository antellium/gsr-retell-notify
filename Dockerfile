FROM python:3.12-slim
WORKDIR /app
COPY poller.py .
ENV PORT=8000
EXPOSE 8000
CMD ["python", "-u", "poller.py"]
