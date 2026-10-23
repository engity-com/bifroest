Generated browser assets are embedded from this directory after `npm run build:app` in web/.
Only this marker belongs in source control. It keeps plain Go/SSH-only source builds possible.
An unbuilt source checkout has no embedded browser application; it still has the HTTP APIs.
