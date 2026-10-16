FROM python:3.12-slim
WORKDIR /app
COPY server.py .
ENV HOST=0.0.0.0 PORT=8099
EXPOSE 8099
USER nobody
CMD ["python", "server.py"]
