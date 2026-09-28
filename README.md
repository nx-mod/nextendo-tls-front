# nextendo-tls-front

TLS termination in front of a local Nextendo stack's HTTP services (production uses Traefik): sni-router passes `accounts.nintendo.com` here, and it forwards by host to `nextendo-account`, BaaS or `nextendo-nnaccount-nx`. Imported from the local stack as found; part of [nextendo-testing](https://github.com/nx-mod/nextendo-testing).

- `TLSFRONT_NNACCOUNT`: Nintendo Account traffic goes to nextendo-nnaccount-nx instead of upstream.
- `TLSFRONT_CAPTURE=<file>`: record `/connect` exchanges.
- HTTP/1.1 only; `TLSFRONT_MAX_TLS12=1` caps TLS at 1.2; each ClientHello and connection state is logged.

`go build` · `TLSFRONT_LISTEN`, `TLSFRONT_CERT`, `TLSFRONT_KEY`.

## Credits

Built by nx-mod for the **Nextendo Network**, on the work of the Nextendo Network team — https://nextendo.network. Nextendo is awesome.
