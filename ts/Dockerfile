# auth-service (TypeScript, meta#103, decision 23 step 7a). Build context is ts/. Nothing deploys from this file until
# the cutover (auth-service#17): container.yml still builds the Go image at the repository root. CI builds this one
# for the `contract-ts` check.
#
# `npm ci --ignore-scripts` everywhere: no dependency's install script runs.

# Build: full dependencies, tsoa codegen, tsc.
FROM node:24-slim AS build
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --ignore-scripts
COPY tsconfig.json tsconfig.build.json tsoa.json ./
COPY scripts ./scripts
COPY src ./src
RUN npm run build

# Production dependencies only, and proof there is no native addon in them: node:sqlite is built in, so a compiled
# file in this tree is a dependency that should not be here (the build fails, naming it).
FROM node:24-slim AS deps
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --ignore-scripts --omit=dev \
 && found="$(find node_modules \( -name '*.node' -o -name '*.so' -o -name '*.so.*' -o -name 'binding.gyp' \))" \
 && if [ -n "$found" ]; then echo "native addon in the production tree:" >&2; echo "$found" >&2; exit 1; fi

# Runtime: no shell, no package manager; the entrypoint is `node`.
#
# nodejs24-debian13, not debian12 as decision 23 says: the debian12 tag is frozen at Node 24.14.0 (deprecated
# upstream), where node:sqlite is still experimental, and the decision's own floor is 24.15 (release candidate). The
# debian13 image is maintained (Node 24.21 at the time of writing). src/runtime.ts refuses to start below 24.15.
#
# Runs as root, the distroless default and what the Go image does: the existing /data/auth.db on the host volume is
# root-owned, and a non-root process could not write it. Changing that needs a volume ownership migration and is a
# post-cutover issue.
FROM gcr.io/distroless/nodejs24-debian13
WORKDIR /app
ENV NODE_ENV=production SQLITE_DB_PATH=/data/auth.db
COPY package.json ./
COPY --from=deps /app/node_modules ./node_modules
COPY --from=build /app/dist ./dist
# The container keeps listening on 80, the port its deployment already publishes; PORT overrides it.
EXPOSE 80
VOLUME ["/data"]
CMD ["dist/server.js"]
