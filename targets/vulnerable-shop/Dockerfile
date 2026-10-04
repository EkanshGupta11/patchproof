FROM node:24-slim

WORKDIR /app

# Install deps first for better layer caching.
COPY package*.json ./
RUN npm install --omit=dev

COPY . .

ENV NODE_ENV=production
ENV PORT=3000
EXPOSE 3000

# Run as the unprivileged user that ships with the node image.
USER node

CMD ["node", "src/server.js"]
