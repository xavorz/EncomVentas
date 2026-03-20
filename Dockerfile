FROM node:18-alpine

WORKDIR /app

# Copy package files
COPY package*.json ./

# Install dependencies (no external deps, but future-proof)
RUN npm install --production 2>/dev/null || true

# Copy application code
COPY . .

# Create data directory
RUN mkdir -p /app/data

# Expose port
EXPOSE 3000

# Run seed (safe: skips if data exists) then start server
CMD ["sh", "-c", "node seed.js && node server.js"]
