FROM python:3.11-slim

WORKDIR /app

# Copy server script
COPY simple_smtp_server.py .

# Make it executable
RUN chmod +x simple_smtp_server.py

# Expose ports
EXPOSE 25 8080

# Run the server
CMD ["python3", "simple_smtp_server.py"]
