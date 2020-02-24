# wstunnel

Tunnel IP over websocket.

Try [a modified version of JSLinux](https://invariant.me/try-jslinux/) to see it working!

## Server usage

```
$ cargo install --git https://github.com/losfair/wstunnel wstunnel
$ wstunnel --help
wstunnel 0.1.0
WebSocket layer 3 tunnel with authentication

USAGE:
    wstunnel [OPTIONS] --config <config> --listen <listen>

FLAGS:
    -h, --help       Prints help information
    -V, --version    Prints version information

OPTIONS:
    -c, --config <config>    Path to config file
    -l, --listen <listen>    Listen address
    -t, --tun <tun>          Name of the local TUN device to use
```

An example config file is available at `test_config.toml`.

## Install as a systemd service

Take a look at `wstunnel.service`. Copy it to `/etc/systemd/system/`, change `/usr/bin/wstunnel` to your binary path and change `/etc/wstunnel.toml` to your configuration path. By default the service listens on `127.0.0.1:1279` and it's suggested to put `wstunnel` behind a secure reverse proxy.
