FROM python:3.11-slim

# Set workdir
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first for better layer caching
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Enable unbuffered logging
ENV PYTHONUNBUFFERED=1

# Gunicorn configuration
ENV PORT=8080

# Expose port for Cloud Run
EXPOSE 8080

# Start the application using Uvicorn via Gunicorn for async support
CMD ["gunicorn", "server:app", "-k", "uvicorn.workers.UvicornWorker", "-b", "0.0.0.0:8080", "--timeout", "180"]

