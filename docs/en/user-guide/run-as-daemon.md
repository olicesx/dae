# Run dae as a Daemon Service

[systemd](https://wiki.debian.org/systemd) allows you to create and manage services in extremely powerful and flexible ways.

> **Note**: (Prerequisites) If your distribution's service manager is provided by systemd.

dae can run as a daemon (systemd) service so that it can run at boot.

## Prerequisites

### Optional Geo Data Files

For more convenient traffic split, dae relies on the following data sources, [geoip.dat](https://github.com/v2fly/geoip/releases/latest) and [geosite.dat](https://github.com/v2fly/domain-list-community/releases/latest).

```shell
mkdir -p /usr/local/share/dae/
pushd /usr/local/share/dae/
curl -L -o geoip.dat https://github.com/v2fly/geoip/releases/latest/download/geoip.dat
curl -L -o geosite.dat https://github.com/v2fly/domain-list-community/releases/latest/download/dlc.dat
popd
```

dae looks for `geoip.dat` and `geosite.dat` in the directory of the config file, then in the platform data directories (`/usr/local/share/dae`, `/usr/share/dae`, `$XDG_DATA_HOME/dae`, ...). To add another directory, set the `DAE_LOCATION_ASSET` environment variable to the directory that holds the `.dat` files:

```bash
DAE_LOCATION_ASSET=/usr/share/v2ray dae run -c /etc/dae/config.dae
```

`DAE_LOCATION_ASSET` is read from the environment of the `dae` process itself. A value you export in an interactive shell does **not** reach a daemon launched by systemd, and `sudo` resets the environment unless you pass `-E`. For a systemd service, put it in a drop-in:

```bash
sudo systemctl edit dae.service
```

```ini
[Service]
Environment=DAE_LOCATION_ASSET=/usr/share/v2ray
```

The shipped unit also reads the optional `/etc/dae/dae.env`, which is not part of the package, so an upgrade cannot overwrite it:

```bash
printf 'DAE_LOCATION_ASSET=/usr/share/v2ray\n' | sudo tee /etc/dae/dae.env
sudo chmod 600 /etc/dae/dae.env
sudo systemctl restart dae
```

When starting `dae` manually, `sudo -E dae run ...` preserves the variable; a bare `sudo dae run ...` does not. Running `dae run ...` without `sudo` as a non-root user also works: dae escalates through `sudo -E` itself and keeps the variable. The error reported when the file is not found names `DAE_LOCATION_ASSET` and whether the process saw it, so the lookup failure is self-explanatory.

### Configuration File

> **Note**: The config file is recommended to save under `/etc/dae`

Download the sample config file:

```bash
mkdir -p /etc/dae
curl -L -o /etc/dae/config.dae https://github.com/olicesx/dae/raw/main/example.dae
chmod 600 /etc/dae/config.dae
```

## Download pre-compiled binaries

Upstream releases are available in <https://github.com/daeuniverse/dae/releases>.
This fork publishes no GitHub Releases: its binaries are the artifacts of the
`Build (Main)` workflow, and its source revisions are tagged `latest`.

> **Note**: If you would like to get a taste of new features, there are nightly (latest) builds available. Most of the time, newly proposed changes will be included in `PRs` and will be exported as cross-platform executable binaries in builds (GitHub Action Workflow Build). Noted that newly introduced features are sometimes buggy, do it at your own risk. However, we still highly encourage you to check out our latest builds as it may help us further analyze features stability and resolve potential bugs accordingly.

This fork's builds are available in <https://github.com/olicesx/dae/actions/workflows/build.yml>

```bash
sudo chmod +x ./dae
sudo install -Dm755 dae /usr/bin/

# helper
dae [-h,--help]
# check version
dae version
```

## Setup

```bash
# download the sample systemd.service
sudo curl -L -o /etc/systemd/system/dae.service https://github.com/olicesx/dae/raw/main/install/dae.service

# reload and restart daemon to take effect
sudo systemctl daemon-reload
sudo systemctl enable dae --now
sudo systemctl status dae
```

## Memory and transparent huge pages

`GOMEMLIMIT` is derived from the process's cgroup ceiling, not from a unit
setting: only `memory.max` participates (the bundled unit no longer sets
`MemoryHigh`, which the runtime cannot observe as a bound), the derived soft
limit is 90% of that ceiling, and an explicit `GOMEMLIMIT` environment variable
always wins.

On a host with transparent huge pages set to `always`, the kernel can inflate
dae's resident set without the live Go heap growing. `disable_thp: true` opts
the process out with `prctl(PR_SET_THP_DISABLE)`; the default (`false`) leaves
the kernel's policy untouched:

```shell
global {
  disable_thp: true
}
```

## Check System Logs

```bash
sudo journalctl -xefu dae
```
