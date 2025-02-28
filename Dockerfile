FROM python:3.11-slim

WORKDIR /app

# Copy requirements file first to leverage cache
COPY requirements.txt /app/

# Install dependencies - this layer will be cached unless requirements.txt changes
RUN pip install --no-cache-dir -r requirements.txt

# Create configuration directory
RUN mkdir -p /etc/trapster

# Copy application code - these are likely to change more frequently
# so we place them after the dependency installation
COPY trapster/data/trapster.conf /etc/trapster/trapster.conf
COPY main.py /app/
COPY trapster /app/trapster/

# Run main.py when the container launches
ENTRYPOINT ["python3", "main.py", "-c", "/etc/trapster/trapster.conf"]