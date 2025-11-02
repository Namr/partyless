# Building

## Project Layout

Partyless is primarily powered by an Axum-based Rust HTTP server, which serves unencrypted HTTP1.1 to server-side rendered routes.
Static content is expected to be served by Nginx (though any static HTTP server will work fine), which also handles TLS & acts as a reverse-proxy
for the Axum server.

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

## Podman Build

Podman is highly recommended to help manage Nginx deployment both while debugging and in production. Podman >= 5.6 is recommended.
You can build the needed containers with the following commands:
```
podman build -f Containerfile.server -t partyless-server .
podman build -f Containerfile.nginx -t partyless-nginx .
```

There are also "Quadlets" to help deploy the server as a systemd service, install those with:
```
sudo podman quadlet install quadlet/
```

## Local Debug Deployment
Assuming the Quadlets were installed from the previous section, a debug nginx server with no TLS can be launched with
```
sudo systemctl start partyless-nginx-debug.service
```
This will serve static content while also acting as a reverse proxy for a server on port 3000 on the host machine. You can launch that server with a simple:
```
cargo run
```
this allows you to rapidly develop the Rust server in debug mode on your host machine while having a containerized and preconfigured Nginx server.

## Production Deployment


