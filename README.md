# BFTKV (to be changed)

BFTKV is a distributed key-value storage which is tolerant to Byzantine fault. See [Design Document](docs/design.md) for details.

###Additional documents:

[HTTP-API](docs/http_api.md)

[Implementation Notes](docs/notes.md)

[Test Notes](docs/tests.md)

## Setup
1. Install [Go 1.8](https://golang.org/doc/install).
2. `go get -u github.com/yahoo/bftkv`
3. Install [GnuPG 1.4](https://www.gnupg.org/download/index.en.html)
4. Make a key directory, e.g. "gnupg.key" and chmod to 700
5. Generate a GPG key pair without password: `gpg --homedir gnupg.key --gen-key`
6. Sign other trusted keys: `trust.sh gnupg.key gnupg.trustKey1 gnupg.trustKey2 gnupg.trustKey3`

## GPG1 vs. GPG2
GPG2 combines _previously separate_ `pubring.pgp` and `secring.pgp` files. Due to this formatting difference, 
changes on the private keys done by using one version will not be visible from the other.
Since BFTKV currently works with the GPG1 format, if you have keys generated using GPG2, private keys need to be
imported to GPG1 with
 
 ```gpg2 --export-secret-keys keyId | gpg --import```

##Build
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

## Run
1. Run a node `bftkv -home gnupg.key`

## Visualization
BFTKV includes a visualization tool (located in `visual/`) for observing the current system state. The tool can display

* Trust graphs for the servers
* Read, write and sign requests sent to the servers
* Revoked and inaccessible servers 

### Write in Action
<img src="docs/images/write.gif" alt="Write"/>

### Revoke on Read in Action
<img src="docs/images/revokeOnRead.gif" alt="Revoke on Read"/> 

## License
Copyright 2017, Yahoo Holdings Inc.

Licensed under the terms of the Apache license. See LICENSE file in project root for terms.
