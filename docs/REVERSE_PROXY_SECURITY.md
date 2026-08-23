# Reverse-proxy security baseline

Nimbus sends its security headers from the application, but an outer reverse
proxy can generate a response before the request reaches Nimbus. Configure the
same baseline at the HTTPS virtual host so method errors, maintenance pages,
and proxy failures do not lose browser protections.

For Plesk, place the `server_tokens`, `if`, and `add_header` directives in the
domain's **Additional nginx directives** field. If Plesk already defines the
proxy location, keep that location and add the `proxy_hide_header` directives
there. Do not define a second competing `location /` block.

```nginx
server_tokens off;

# Reject TRACE at the outermost layer. `return` is safe in this context.
if ($request_method = TRACE) { return 405; }

add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
add_header Content-Security-Policy "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'" always;
add_header X-Content-Type-Options "nosniff" always;
add_header X-Frame-Options "DENY" always;
add_header Referrer-Policy "no-referrer" always;
add_header Cross-Origin-Opener-Policy "same-origin" always;
add_header Cross-Origin-Resource-Policy "same-origin" always;
add_header Permissions-Policy "camera=(), microphone=(), geolocation=(), payment=(), usb=()" always;
```

For a manually managed Nginx virtual host, use the following proxy location.
The `proxy_hide_header` lines prevent duplicate copies of the same headers from
the upstream application; Nginx then applies the virtual-host values to every
response with `always`.

```nginx
location / {
    proxy_pass http://10.0.0.101:4173;
    proxy_http_version 1.1;

    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;
    proxy_set_header Upgrade $http_upgrade;
    proxy_set_header Connection "upgrade";

    proxy_buffering off;
    proxy_request_buffering off;
    client_max_body_size 9g;
    proxy_read_timeout 2h;
    proxy_send_timeout 2h;

    proxy_hide_header Strict-Transport-Security;
    proxy_hide_header Content-Security-Policy;
    proxy_hide_header X-Content-Type-Options;
    proxy_hide_header X-Frame-Options;
    proxy_hide_header Referrer-Policy;
    proxy_hide_header Cross-Origin-Opener-Policy;
    proxy_hide_header Cross-Origin-Resource-Policy;
    proxy_hide_header Permissions-Policy;
}
```

Keep `Cache-Control` under Nimbus's control: authenticated and console content
is non-cacheable, while pinned public console renderer modules intentionally use
a bounded public cache. If the proxy replaces error bodies, ensure its custom
error documents do not reflect request input and explicitly set
`Cache-Control: no-store` on those error locations.

After deployment, compare the header baseline on representative success and
error responses:

```bash
curl -sS -D- -o /dev/null https://panel.example.com/
curl -sS -X TRACE -D- -o /dev/null https://panel.example.com/
curl -sS -D- -o /dev/null https://panel.example.com/definitely-missing.txt
```

The TRACE request must be rejected, and all three responses should retain HSTS,
CSP, `nosniff`, framing, referrer, cross-origin, and permissions headers.
