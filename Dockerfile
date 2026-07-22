FROM node:24-alpine

WORKDIR /app

COPY package.json pnpm-lock.yaml server.mjs ./
RUN corepack enable && pnpm install --prod --frozen-lockfile --ignore-scripts

COPY public ./public
COPY server ./server
COPY scripts ./scripts
COPY migrations ./migrations
COPY docs ./docs

ENV NODE_ENV=production \
    HOST=0.0.0.0 \
    PORT=4173 \
    DATA_DIR=/data

RUN mkdir -p /data && chown node:node /data

EXPOSE 4173

VOLUME ["/data"]

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD wget -qO- http://127.0.0.1:4173/api/health >/dev/null || exit 1

USER node

CMD ["node", "server.mjs"]
