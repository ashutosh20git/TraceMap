FROM node:22.12-alpine
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --omit=dev
COPY server.js ./
USER node
EXPOSE 3001
CMD ["node", "server.js"]
