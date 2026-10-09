FROM node:20-alpine
WORKDIR /app
COPY package*.json ./
RUN npm ci --omit=dev
COPY . .
ENV PORT=3000 DATA_DIR=/data
VOLUME /data
EXPOSE 3000
CMD ["node", "server/index.mjs"]
