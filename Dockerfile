FROM node:22-slim

# Create non-root user for security
RUN groupadd -r hivetrust && useradd -r -g hivetrust hivetrust

WORKDIR /app

# Copy package files first for layer caching
COPY package*.json ./

# Install production dependencies only
RUN npm ci --omit=dev

# Copy application source
COPY . .

# Create data directory for SQLite and set permissions
RUN mkdir -p data && chown -R hivetrust:hivetrust /app

# Switch to non-root user
USER hivetrust

# Expose HiveTrust default port (distinct from HiveAgent's 3000)
EXPOSE 3001

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=15s --retries=3 \
  CMD node -e "fetch('http://localhost:3001/health').then(r=>r.ok?process.exit(0):process.exit(1)).catch(()=>process.exit(1))"

# Start the server
CMD ["node", "start.js"]
