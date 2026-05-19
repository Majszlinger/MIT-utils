# FastAPI Email Reference App

Small reference app showing how to use `mit_utils[email]` from a FastAPI
service. It exposes Dimail and Microsoft Graph email endpoints and keeps
credentials in environment variables.

## Configuration

Copy the example environment file and fill in your Dimail key:

```bash
cp examples/fastapi_email/.env.example examples/fastapi_email/.env
```

Required for Dimail:

- `DIMAIL_API_KEY`

Optional for Dimail:

- `DIMAIL_HOST`, defaults to `https://admin.dimail.hu`
- `DIMAIL_TIMEOUT`, defaults to `15`

Required for Microsoft Graph:

- `MS_GRAPH_TENANT_ID`
- `MS_GRAPH_CLIENT_ID`
- `MS_GRAPH_CLIENT_SECRET`
- `MS_GRAPH_SENDER_EMAIL`

Optional for Microsoft Graph:

- `MS_GRAPH_TIMEOUT`, defaults to `10`
- `MS_GRAPH_BASE_URL`, defaults to `https://graph.microsoft.com/v1.0`

The Azure app registration must have the Microsoft Graph application
permission needed to send mail for `MS_GRAPH_SENDER_EMAIL`, such as `Mail.Send`,
with admin consent granted.

Do not commit `.env` or real secret values.

## Docker

Build from the repository root so Docker installs this local package with the
`email` extra:

```bash
docker build -f examples/fastapi_email/Dockerfile -t mit-utils-email-example .
```

Run with environment values supplied externally:

```bash
docker run --env-file examples/fastapi_email/.env -p 8000:8000 mit-utils-email-example
```

Open:

```bash
curl http://localhost:8000/health
```

Swagger UI is available at:

```text
http://localhost:8000/docs
```

## Endpoints

- `GET /health`
- `POST /graph/send`
- `POST /dimail/send`
- `GET /dimail/status/{send_id}`
- `GET /dimail/lists`
- `POST /dimail/lists`
- `DELETE /dimail/lists/{list_id}`
- `POST /dimail/lists/{list_id}/subscribe`
- `POST /dimail/lists/{list_id}/unsubscribe`
- `GET /dimail/newsletters`
- `POST /dimail/newsletters`
- `PUT /dimail/newsletters/{newsletter_id}`
- `POST /dimail/newsletters/{newsletter_id}/send`
- `GET /dimail/newsletters/{newsletter_id}/statistics`
- `POST /dimail/campaigns`
- `DELETE /dimail/campaigns/{campaign_id}`
- `POST /dimail/campaigns/{campaign_id}/lists`
- `POST /dimail/campaigns/{campaign_id}/newsletters/{newsletter_id}`
- `POST /dimail/login-token`

## Newsletter Workflow

Use this sequence for a bulk newsletter send:

1. Create or choose a subscriber list with `GET /dimail/lists` or `POST /dimail/lists`.
2. Subscribe users with `POST /dimail/lists/{list_id}/subscribe`.
3. Create a campaign with `POST /dimail/campaigns`.
4. Attach list IDs to the campaign with `POST /dimail/campaigns/{campaign_id}/lists`.
5. Create newsletter content with `POST /dimail/newsletters`.
6. Attach the campaign to the newsletter with `POST /dimail/campaigns/{campaign_id}/newsletters/{newsletter_id}`.
7. Send the newsletter with `POST /dimail/newsletters/{newsletter_id}/send`.

Example send request:

```bash
curl -X POST http://localhost:8000/dimail/send \
  -H "Content-Type: application/json" \
  -d "{\"to\":\"user@example.com\",\"subject\":\"Welcome\",\"html_message\":\"<p>Hello</p>\"}"
```

Example newsletter request:

```bash
curl -X POST http://localhost:8000/dimail/newsletters \
  -H "Content-Type: application/json" \
  -d "{\"subject\":\"Monthly update\",\"html_message\":\"<p>Hello subscribers</p>\",\"text_message\":\"Hello subscribers\"}"
```

Example campaign request:

```bash
curl -X POST http://localhost:8000/dimail/campaigns \
  -H "Content-Type: application/json" \
  -d "{\"name\":\"Monthly campaign\"}"
```

Example campaign list assignment:

```bash
curl -X POST http://localhost:8000/dimail/campaigns/123/lists \
  -H "Content-Type: application/json" \
  -d "{\"list_ids\":[\"7874\"]}"
```

Example campaign/newsletter attachment:

```bash
curl -X POST http://localhost:8000/dimail/campaigns/123/newsletters/456
```

## Microsoft Graph

Use `POST /graph/send` when an app should send through Microsoft 365 instead
of Dimail. The sender mailbox comes from `MS_GRAPH_SENDER_EMAIL`; callers only
provide recipients and message content.

Example Graph send request:

```bash
curl -X POST http://localhost:8000/graph/send \
  -H "Content-Type: application/json" \
  -d "{\"to_recipients\":[\"user@example.com\"],\"subject\":\"Welcome\",\"body\":\"Hello from Microsoft Graph\",\"body_content_type\":\"Text\"}"
```

The response only confirms that Microsoft Graph accepted the request:

```json
{
  "ok": true,
  "provider": "graph",
  "payload": {
    "accepted": true
  }
}
```
