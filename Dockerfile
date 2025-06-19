FROM node:22-bookworm AS build-stage

RUN mkdir /app
WORKDIR /app
COPY ./ /app

RUN mkdir /root/.ssh
RUN chmod 0700 /root/.ssh
RUN echo "Host github.com\n\tHostname ssh.github.com\n\tPort 443" >> /root/.ssh/config
RUN ssh-keyscan -p 443 ssh.github.com  >> /root/.ssh/known_hosts

RUN --mount=type=ssh  \
    yarn install --production --frozen-lockfile  &&  \
    yarn cache clean --force

# production stage
FROM node:22-bookworm-slim AS production-stage

COPY --from=build-stage /app/ /app/

WORKDIR /app

CMD ["node", "server.js"]
