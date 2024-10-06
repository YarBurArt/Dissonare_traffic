# Base image
FROM python:3.10-slim

# Set working directory
WORKDIR /app

# Copy and install dependencies
COPY pyproject.toml poetry.lock* /app/
RUN  pip install --upgrade pip && pip install --no-cache-dir poetry && poetry install --no-dev

# Copy from root folder application code
COPY . /app

# Run the app
CMD ["poetry", "run", "uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8080", "--reload"]

EXPOSE 8080
