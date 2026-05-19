FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

WORKDIR /opt/mit-utils

COPY . /opt/mit-utils

RUN pip install --no-cache-dir -r examples/fastapi_email/requirements.txt \
    && pip install --no-cache-dir "/opt/mit-utils[email]"

WORKDIR /opt/mit-utils/examples/fastapi_email

EXPOSE 8000

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
