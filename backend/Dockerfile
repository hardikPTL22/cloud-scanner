FROM ghcr.io/astral-sh/uv:python3.13-bookworm

WORKDIR /app

COPY . .

RUN uv sync --locked

EXPOSE 5000

CMD ["uv", "run", "fastapi", "dev", "app.py", "--port", "5000", "--host", "0.0.0.0"]
