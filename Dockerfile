FROM python:3.12-slim
WORKDIR /app
COPY pyproject.toml uv.lock ./
COPY agent_perimeter ./agent_perimeter
# alembic.ini + migrations/ are needed inside the image too: docker-compose's
# `api` service runs `alembic upgrade head` on start and scripts/smoke.sh
# execs `alembic current` in the running container (task 17 Step 2). alembic
# and uvicorn are both `pip install .` console scripts already (both are
# direct pyproject.toml dependencies) -- no separate `uv` install needed
# inside this image, which only ever runs the built package, not `uv run`.
COPY alembic.ini ./
COPY migrations ./migrations
RUN pip install --no-cache-dir .
ENTRYPOINT ["agent-perimeter"]
