# Tests
* All tests: `go test -v`
  * Note: When all tests are run, -r must be small enough that the number of open files does not exceed the maximum limit as allowed by os. The default value, 10, is small enough to keep the number of open files << 1024 (default Linux/Unix open file maximum) when the tests run concurrently.
* Server test: `go test -run=TestServer -v`
  * TestServer: Creates servers and a client. Client writes to and then reads value from servers.
* TOFU tests: `go test -run=TOFU -v`
  * A client writes to x for the first time: <x, t, v> - expected: write successful
  * The same client overwrites <x, t, v> with <x, t', v'> - expected: write successful
  * A client with a different id but same uid as the previous client overwrites <x, t', v'> with <x, t'', v''> - expected: write successful
  * A client with neither the id or uid of the previous client, attempts to overwrite <x, t'', v''> with <x, t''', v'''> - expected: invalid quorum certificate
* Revoke tests: `go test -run=Revoke -v`
  * TestRevokeNone: Generates a map of times, values and signatures corresponding to a given key. Each signature signed only one value given some <x, t>. Each writer wrote only one value given some <x, t>
  * TestRevokeMaliciousClientColludingServer: Generates a map of times, values and signatures corresponding to a given key. Some signers/writers, signed/wrote more than one value given some <x, t>. These signers/writers will be revoked. 
* Run malicious client/server test: `go test -run=Collusion -v`
  * TestMaliciousCollusion: A malicious client writes <x, t, v> and <x, t, v'> to colluding servers. The colluding servers signed both values. An honest client will be able to identify and revoke the malicious writers/signers (assuming n >= 3f + 1).
* Read/Write timing tests: `go test -run=Many -v`
  * TestManyWrites: Prints average time of write. Optional parameter -r specifies number of writes to take the average of. Default is 100. Writes are sequential.
  * TestManyReads: Prints average time of read. Optional parameter -r specifies number of reads to take average of. Default is 100. Reads are sequential.
* Read/Write concurrency tests: `go test -run=Concurrent`
  * TestManyClientsConcurrentReads: Optional parameter -r specifies number of concurrent reads by each client. Default is 10. Note, this number can only be as high as maximum number of open files/number of clients as allowed by os.
  * TestManyClientsConcurrentWrites: Optional parameter -r specifies number of concurrent writes by each client. Default is 10. Note, this number can only be as high as maximum number of open files/number of clients as allowed by os.
* Conflict test: `go test -run=Conflict -v`
  * TestConflict: Has n different clients concurrently write a value to the same key. Expected: n-1 invalid signature requests and 1 successful write. Invalid signature requests are returned by signers who cannot sign some value because a different client has already written to that key.
