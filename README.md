# webauthn-example
webauthn-example with go, vite, react, and typescript. data backed by redis and postgres.

for mvp:

```sh
cd views
npm run build

cd ..
docker-compose up
```

for development:

```sh
cd views
npm run build:watch

cd ..
docker-compose up
```

## TODOs

- UI and persist display name
- persist credentials table for 1 to many relationship with user table.

## Reference
- https://www.corbado.com/blog/webauthn-user-id-userhandle#webauthn-credential-id
- https://www.corbado.com/blog/passkey-webauthn-database-guide
