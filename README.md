# Render Key Manager

## Deploy
1. Upload these files to a GitHub repository.
2. In Render, create a Web Service from the repository. You can use the included `render.yaml` Blueprint.
3. Ensure the service has a persistent disk mounted at `/var/data`.
4. In Render Environment, set strong secret values for `ADMIN_TOKEN` and `KEY_PEPPER`. Keep them private.
5. Deploy. Admin console is at the service root `/`.

## API
- `POST /api/add_key` (admin header `X-Admin-Token`) body: `{"duration":7,"unit":"days"}` or `{"duration_seconds":3600}`
- `GET /api/get_key` (admin only): unused key metadata/prefixes. Full key is shown only once at creation.
- `GET /api/key_status` (admin only): latest key status metadata.
- `POST /api/verify_key` body: `{"key":"DV-...","device_id":"stable-device-id"}`
- `POST /api/delete_key` (admin only) body: `{"id":123}`
- `GET /health`

## User-side integration
Call `POST https://YOUR-SERVICE.onrender.com/api/verify_key` with JSON `{ "key": enteredKey, "device_id": stableDeviceId }`.
Persist the same stable device ID on the client. Do not use a newly generated ID on every app launch.
The server binds first activation to a hash of the device ID. The same device can re-check the key; a different device receives `KEY_ALREADY_USED`.

## Important security notes
- Do not expose `ADMIN_TOKEN` in your public app, browser JavaScript, or user HTML. Admin calls belong only in the admin console or a trusted server.
- The included admin page is served by the same Flask service; it asks for the token at runtime.
- The server stores key hashes, not raw keys. Therefore `/get_key` returns unused key references/prefixes, not recoverable full key strings. Copy the full key immediately after generating it.
- Device IDs supplied by a client can be spoofed by a determined user. For stronger binding, issue a signed device identity from a trusted app/backend and add platform attestation.
- Configure `ALLOWED_ORIGINS` to your actual site origins instead of `*` when the client is hosted separately.
- Keep the Render persistent disk attached; without it, SQLite data may be lost on redeploy/restart.
