# Use an official Python runtime as a parent image
FROM python:3.11-slim

# Set the working directory in the container
WORKDIR /app

# Copy the needed files into the container at /app
RUN mkdir -p /etc/trapster
COPY trapster/data/trapster.conf /etc/trapster/trapster.conf
COPY main.py /app
COPY trapster /app/trapster
COPY requirements.txt /app

# Install any needed packages specified in requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# Run main.py when the container launches
ENTRYPOINT ["python3", "main.py", "-c", "/etc/trapster/trapster.conf"]