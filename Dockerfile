FROM python:3.11-slim

WORKDIR /app

# Install Poetry
RUN pip install poetry

# Copy only the files necessary for installing dependencies
COPY poetry.lock pyproject.toml /app/

# Install dependencies
RUN poetry config virtualenvs.create false && poetry install --only main --no-interaction --no-ansi --no-root

# Copy the rest of the application
COPY . /app/

# Expose the port the app runs on
EXPOSE 8000

# Run the application
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"] 