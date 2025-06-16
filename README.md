# webauthn-example
webauthn-example with go, vite, react, and typescript. data backed by redis and postgres.

for mvp:

```sh
cd views
npm run build
echo "VITE_API_URL={HOST_URL}" > .env.production

cd ..
# docker-compose file supply env for prod
docker-compose up
```

for development:

```sh
cd views
echo "VITE_API_URL=http://localhost:8080" > .env
npm run build:watch

cd ..
docker-compose up
```

development envs for containers:

```sh
PGPORT=5432
PGPASSWORD=webauthnpassword
PGHOST=localhost
PGUSER=webauthn
PGDATABASE=webauthn_db

DATABASE_HOST=webauthn-db
DATABASE_USER=webauthn
DATABASE_PORT=5432
DATABASE_PASS=webauthnpassword
DATABASE_URL=postgres://${DATABASE_USER}:${DATABASE_PASS}@${DATABASE_HOST}:${DATABASE_PORT}/${PGDATABASE}?sslmode=disable

REDIS_URL=webauthn-redis:6379
```

remove `user: 501:501` in docker-compose file if mount volume instead.

## TODOs

- UI and persist display name
- persist credentials table for 1 to many relationship with user table.
- refactor app logic with https://github.com/samber/mo 
  - Try monad cannot chain with FlatMap
  - may drop out the FP replacement for app logic
- refactor error response handling by `types.RespondWithError`
  - registration
  - session
  - user
- consider meaningful error types instead log error
- 

## Reference
- https://www.corbado.com/blog/webauthn-user-id-userhandle#webauthn-credential-id
- https://www.corbado.com/blog/passkey-webauthn-database-guide
