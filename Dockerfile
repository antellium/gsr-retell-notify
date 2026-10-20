FROM python:3.12-slim
WORKDIR /app
RUN pip install --no-cache-dir tzdata
COPY poller.py blocked_numbers.txt ./
ENV PORT=8000
EXPOSE 8000
CMD ["python", "-u", "poller.py"]
