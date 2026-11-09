# Production Dockerfile for CyberDost
FROM node:22-alpine

WORKDIR /app

# Copy project files
COPY package.json ./
COPY server.js cli.js ./
COPY src/ ./src/
COPY public/ ./public/

# Expose server port
EXPOSE 3000

ENV PORT=3000
ENV HOST=0.0.0.0

CMD ["node", "server.js"]
