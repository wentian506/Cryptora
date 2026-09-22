# JURY DEMO FIXTURE — container signals
FROM node:18
RUN apt-get update && apt-get install -y openssl openssh-client
COPY server.key /app/server.key
EXPOSE 8080
CMD ["node", "server.js"]
