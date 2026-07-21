FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Make startup script executable before dropping to non-root user
RUN chmod +x start.sh

RUN groupadd -r mcp && useradd -r -g mcp -d /app -s /sbin/nologin mcp \
    && chown -R mcp:mcp /app
USER mcp

EXPOSE 8000

# start.sh runs migrate.py first, then uvicorn.
# In docker-compose (local), the separate migrate service handles migrations
# and this script still works fine (schema files are idempotent).
# In Railway (production), this is the only startup path.
CMD ["./start.sh"]