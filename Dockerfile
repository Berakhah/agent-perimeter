FROM python:3.12-slim
WORKDIR /app
COPY pyproject.toml uv.lock ./
COPY agent_perimeter ./agent_perimeter
RUN pip install --no-cache-dir .
ENTRYPOINT ["agent-perimeter"]
