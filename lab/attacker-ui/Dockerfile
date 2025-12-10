FROM node:20-alpine

WORKDIR /app
COPY index.html server.js ./
COPY js ./js
COPY css ./css

ENV PORT=4170
EXPOSE 4170
USER node
CMD ["node", "server.js"]
