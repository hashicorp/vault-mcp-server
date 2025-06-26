FROM node:22-bookworm AS build-stage

WORKDIR /app
COPY package.json yarn.lock ./
RUN --mount=type=ssh yarn install --production --frozen-lockfile && yarn cache clean --force

COPY . .

# production stage
FROM node:22-alpine AS production-stage

WORKDIR /app

# Only copy production dependencies and built files
COPY --from=build-stage /app/node_modules ./node_modules
COPY --from=build-stage /app/. /app/

# Remove unnecessary files (docs, tests, etc.) if possible
RUN rm -rf /app/.git /app/tests /app/test /app/docs /app/.github || true

CMD ["node", "sse-server.js"]
