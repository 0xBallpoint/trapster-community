FROM python:3.11-slim

WORKDIR /app

# Copy setup files first to leverage cache for dependency installation
COPY requirements.txt setup.py MANIFEST.in README.md /app/
COPY trapster/__init__.py /app/trapster/__init__.py

# Install the package with AI features enabled
# This will install both base requirements and AI extras
RUN pip install --no-cache-dir .[ai]

# Create configuration directory
RUN mkdir -p /etc/trapster

# Copy application code - these are likely to change more frequently
# so we place them after the dependency installation
COPY trapster/data/trapster.conf /etc/trapster/trapster.conf
COPY main.py /app/
COPY trapster /app/trapster/

# Run main.py when the container launches
ENTRYPOINT ["python3", "main.py", "-c", "/etc/trapster/trapster.conf"]