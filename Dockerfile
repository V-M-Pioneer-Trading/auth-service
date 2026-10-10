# auth-service (TypeScript, meta#103, decision 23). Build context is the repository root. container.yml builds this
# file for linux/arm64 (the shared host is a Graviton t4g) and the `contract` job builds it for the black-box suite.
#
# `npm ci --ignore-scripts` everywhere: no dependency's install script runs.

# Build: full dependencies, tsoa codegen, tsc.
FROM node:24-slim@sha256:d6aa754f16b3197301076f047b5def2f02ea1dbbc2ca920407d46d7ec7f87b20 AS build
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --ignore-scripts
COPY tsconfig.json tsconfig.build.json tsoa.json ./
COPY scripts ./scripts
COPY src ./src
RUN npm run build

# Production dependencies only (optional ones too are left out: `npm ci --omit=dev` still installs a dev dependency that is
# also an optional one of something that ships), proof there is no compiled code in them (by extension and by magic
# bytes: node:sqlite is built in, so a native addon here is a dependency that should not be), and then the packages
# nothing loads removed: @tsoa/runtime declares @hapi/* for its hapi adapter and @types/* for its typings, and a test
# (runtimeTree.test.ts) boots dist/server.js and fails if either is required.
FROM node:24-slim@sha256:d6aa754f16b3197301076f047b5def2f02ea1dbbc2ca920407d46d7ec7f87b20 AS deps
WORKDIR /app
COPY package.json package-lock.json ./
COPY scripts/find-native.cjs ./scripts/find-native.cjs
RUN npm ci --ignore-scripts --omit=dev --omit=optional \
 && node scripts/find-native.cjs node_modules \
 && rm -rf node_modules/@hapi node_modules/@types

# Runtime: no shell, no package manager; the entrypoint is `node`.
#
# nodejs24-debian13, not debian12 as decision 23 says: the debian12 tag is frozen at Node 24.14.0 (deprecated
# upstream), where node:sqlite is still experimental, and the decision's own floor is 24.15 (release candidate). The
# debian13 image is maintained (Node 24.21 at the time of writing). src/runtime.ts refuses to start below 24.15.
#
# Runs as root, the distroless default and what the Go image did: the existing /data/auth.db on the host volume is
# root-owned, and a non-root process could not write it. Changing that needs a volume ownership migration and is a
# post-cutover issue.
FROM gcr.io/distroless/nodejs24-debian13@sha256:96df910f65fdd8a21d00d14d4cc046adcfcf3ced2d5e96be4b39ebde9f4866c6
WORKDIR /app
ENV NODE_ENV=production SQLITE_DB_PATH=/data/auth.db
COPY package.json ./
COPY --from=deps /app/node_modules ./node_modules
COPY --from=build /app/dist ./dist
# The container keeps listening on 80, the port its deployment already publishes; PORT overrides it.
EXPOSE 80
VOLUME ["/data"]
CMD ["dist/server.js"]
