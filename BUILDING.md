# Building

## Project Layout

Partyless is primarily powered by an Axum-based Rust HTTP server, which serves unencrypted HTTP1.1 to server-side rendered routes.
A reverse proxy like Caddy is expected to provide TLS.

## Local Build

The Rust backend depends on the sqlite3 development libraries. How you install these depends on your distro
e.g Fedora:
```
sudo dnf install sqlite sqlite-devel
```
or on Debian/Ubuntu:
```
sudo apt install libsqlite3-dev
```

Then build the server with 
```
cargo build
```

You can run a local development version with just
```
cargo run
```
Which serves the website on port 3000. Use the `--release` flag for release builds.

## Podman Build

Podman can be used to ease the build & deployment process. Podman >= 5.6 is recommended.
You can build the needed container with the following command (while in the repo root directory):
```
podman build -t partyless_server:0.1.0 .
```

You can run the container with the following command:
```
podman run --net=host -p=3000 -v /var/db/partyless:/app/data:Z partyless_server:0.1.0
```

This places the sqlite db files in /var/db/partyless on your host machine, which may require root privileges.

## Production Deployment

Build the Podman server image as described above, and export the container image to an OCI archive:
```
podman save --format oci-archive -o partyless_server_0.1.0.oci.tar partyless_server:0.1.0
```

Transfer this file to your host server. and load it with the following command:
```
podman load -i partyless_server_0.0.1.oci.tar
```

Its recommended to use a systemd service to run the server, make a systemd service file at `/etc/systemd/system/partyless.service`.
An example service file can be found below:
```
[Unit]
Description=Partyless Server
After=network.target
StartLimitIntervalSec=0

[Service]
Type=simple
Restart=always
RestartSec=1
ExecStart=podman run --net=host -p=3000 -v /var/db/partyless:/app/data:Z partyless_server:0.1.0

[Install]
WantedBy=multi-user.target
```

Then start the server with
```
sudo systemctl daemon-reload
sudo systemctl enable --now partyless.service
```

The server will now be running on port 3000. You will need a reverse proxy for TLS, here's an example Caddy file for https://partyless.rsvp:
```
partyless.rsvp

reverse_proxy :3000
```

