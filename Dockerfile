FROM python:3.13-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY ai-engine/ ai-engine/
COPY backend/ backend/
COPY simulator/ simulator/
COPY docs/ docs/
ENV PYTHONUNBUFFERED=1
EXPOSE 8000
CMD ["uvicorn", "watchtower.app:app", "--app-dir", "backend", "--host", "0.0.0.0", "--port", "8000"]
