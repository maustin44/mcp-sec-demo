# ToolVault Backend — Production Dockerfile
FROM node:20-alpine

WORKDIR /app

# Install dependencies first (better layer caching)
COPY package*.json ./
RUN npm ci --only=production

# Copy source
COPY . .

# SQLite data directory
RUN mkdir -p /app/data

EXPOSE 3001

CMD ["node", "server.js"]
