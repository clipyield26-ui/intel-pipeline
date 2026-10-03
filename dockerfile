FROM python:3.12-alpine AS build
WORKDIR /app
RUN apk add --no-cache build-base libffi-dev
COPY requirements.txt.
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt

FROM python:3.12-alpine
WORKDIR /app
RUN adduser -D -u 10001 appuser && apk add --no-cache libstdc++
COPY --from=build /install /usr/local
COPY main.py.
RUN chown -R appuser:appuser /app
USER appuser
EXPOSE 8000
ENV PYTHONUNBUFFERED=1
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "2"]
