# zen — ZIA Central Authority Simulator

Run the demo server locally (requires PostgreSQL and Redis):

1. Start dependencies with Docker Compose:

```bash
docker-compose up --build
```

2. Build and run the server locally (if you prefer):

```bash
go build ./cmd/server
./server
```

3. Example: create a SAML session

```bash
curl -X POST localhost:8080/api/v1/auth/saml -H "Content-Type: application/json" -d '{"name_id":"janu@acme.com","session_idx":"s001","user_id":"u123","groups":["eng"],"policy_epoch":5,"expires_in_sec":3600,"idp_entity_id":"https://sts.windows.net/abc"}'
```