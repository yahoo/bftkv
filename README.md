# BFTKV (to be changed)

BFTKV is a distributed key-value storage which is tolerant to Byzantine fault. See [Abstract](docs/design.md) for details.

### Additional documents:
[Design Document (restricted)](https://docs.google.com/document/d/14xYeGR291UKba1pimO9DnFNvfZ3ceTYsfbWZbgpWkTQ/edit?usp=sharing)

[Paper (draft)](docs/bftkv.pdf)

[HTTP-API](docs/http_api.md)

[Implementation Notes](docs/notes.md)

[Test Notes](docs/tests.md)

## Setup
1. Install [Go 1.8](https://golang.org/doc/install).
2. `go get -u github.com/yahoo/bftkv`
3. Install [GnuPG 2.x](https://www.gnupg.org/download/index.en.html)
4. Install [Docker](https://www.docker.com) (if you want to run BFTKV in a Docker container)
5. Run `setup.sh` in scripts (`setup.sh -host bftkv` for Docker)
6. If bftkv runs with KeyTransparency, run `$GOPATH/src/github.com/google/keytranspreancy/scripts/gen_bftkv_keys.sh`

## Build
```
cd /github.com/yahoo/bftkv
go build -o bftkv cmd/main.go
```

## Parameters
A list of parameters that can be supplied to bftkv is given below:

<pre>
<b>Flag</b>     <b>Purpose </b>                              <b>Default</b>
-home    Path to PGP home directory,           ~/.gnupg
-sec     Secret key ring path,                 $home/secring.gpg
-pub     Public key ring path,                 $home/pubring.gpg
-rev     Revocation list path,                 $home/revocation.gpg
-db      Database path,                        db
-api     Http api address,                     localhost:5792
-ws      Web socket port,                      5001
</pre>

## Run Options
1. Run a node `bftkv -home gnupg.key`

2. Run a BFTKV cluster `cd scripts/run; ../run.sh`

3. Run a BFTKV cluster in Docker

```
docker build -t bftkv .
docker run -d bftkv
```

## Visualization
BFTKV includes a visualization tool (located in `visual/`) for observing the current system state. The tool can display

* Trust graphs for the servers
* Read, write and sign requests sent to the servers
* Revoked and inaccessible servers 

To show the graph, run `run.sh` and `open visual/index.html`.

### Write in Action
<img src="docs/images/write.gif" alt="Write"/>

### Revoke on Read in Action
<img src="docs/images/revokeOnRead.gif" alt="Revoke on Read"/> 

## License
Copyright 2017, Yahoo Holdings Inc.

Licensed under the terms of the Apache license. See LICENSE file in project root for terms.
