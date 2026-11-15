FROM node:22-bookworm-slim

WORKDIR /app

# Pantegnos for NPVS / EHI / HC / heavy formats
RUN apt-get update && apt-get install -y --no-install-recommends curl ca-certificates \
  && curl -sL -o /tmp/p.tgz https://github.com/FrontierTM/Pantegnos/releases/download/v9.4.5/pantegnos-linux-amd64.tar.gz \
  && tar -xzf /tmp/p.tgz -C /usr/local/bin pantegnos \
  && chmod +x /usr/local/bin/pantegnos \
  && rm -rf /tmp/p.tgz /var/lib/apt/lists/*

COPY package.json ./
RUN npm install --omit=dev

COPY src ./src

ENV PORT=3000
ENV NODE_ENV=production
EXPOSE 3000

CMD ["npm", "start"]
