FROM node:20-alpine
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci
COPY . .
# NEXT_PUBLIC_* variables are inlined into the client bundle at build time,
# not read at container start -- must be a build ARG, not just a runtime
# `environment:` entry in docker-compose.yml. Default matches .env.example.
ARG NEXT_PUBLIC_API_BASE_URL=http://localhost:8000
ENV NEXT_PUBLIC_API_BASE_URL=$NEXT_PUBLIC_API_BASE_URL
# ponytail: single-stage build (full node_modules + source stay in the final
# image, no `output: "standalone"` in next.config.ts) -- larger image than a
# multi-stage build, but zero changes to next.config.ts for a project that
# doesn't already use standalone output. Switch to a standalone multi-stage
# build if image size becomes a real constraint.
RUN npm run build
EXPOSE 3000
CMD ["npm", "run", "start"]
