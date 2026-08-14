# portrecon

A small threaded TCP port scanner with banner grabbing. Built this because I
wanted something faster than firing up a full nmap run for a quick "what's
open on this box" check during recon, and something I could tweak myself
without fighting a huge codebase.

No external dependencies - just the Python standard library, so it runs
anywhere Python 3.6+ is installed.

## What it does

- Threaded connect() scans (default 200 workers, configurable)
- Grabs whatever banner the service offers on connect, with an HTTP HEAD
  nudge for common web ports
- Falls back to a small lookup table of common ports when there's no banner
- Optional JSON output for feeding into other tools/scripts

## Usage

```
python3 portrecon.py 10.0.0.5
python3 portrecon.py 10.0.0.5 -p 1-1000
python3 portrecon.py scanme.nmap.org -p 22,80,443,8080 --json results.json
```

```
usage: portrecon.py [-h] [-p PORTS] [-t THREADS] [--timeout TIMEOUT] [--json FILE] [-q] target

positional arguments:
  target                hostname or IP to scan

options:
  -h, --help            show this help message and exit
  -p PORTS, --ports PORTS
                        ports/ranges, e.g. '22,80,443' or '1-1024' (default: 1-1024)
  -t THREADS, --threads THREADS
                        worker threads (default: 200)
  --timeout TIMEOUT     per-port timeout in seconds
  --json FILE           also write results as JSON to this file
  -q, --quiet           only print open ports
```

## Notes / limitations

This is a plain connect() scanner, not a SYN scanner, so it's noisier than
nmap's default and won't do OS fingerprinting or UDP. It's meant for quick
checks on hosts you're authorized to test, not for stealth. If you need
something more thorough, use nmap or masscan instead - this is just the
tool I reach for when I want a fast answer and don't want to leave the
terminal.

Only run this against systems you own or have explicit permission to test.

## License

MIT, see LICENSE.
