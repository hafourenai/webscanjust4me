# Use official Python slim image
FROM python:3.10-slim

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# Set working directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    python3-dev \
    && rm -rf /var/lib/apt/lists/*

# Create directories for logs and reports
RUN mkdir -p logs reports

# Copy requirements and install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy project files
COPY . .

# Install the project
RUN pip install --no-cache-dir .

# Create a non-root user and switch to it
RUN useradd -m honeyuser && chown -R honeyuser:honeyuser /app
USER honeyuser

# Define volumes for logs and reports
VOLUME ["/app/logs", "/app/reports"]

# Entry point
ENTRYPOINT ["honey-scanner"]
CMD ["--help"]
