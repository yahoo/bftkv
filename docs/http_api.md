# HTTP API
BFTKV node exposes two functions via HTTP API (for debugging purpose only): 

1. `/read/key`, `GET` request returns the value associated with the `key`

**Example**:

```
curl http://httpApiAddress/read/test // assuming the system stores <"test", "this is a test">, returns "this is a test"
```

2. `/write/key`, `POST` request stores the data carried by the request as a key-value pair (i.e. <"key", data>).

**Example**:

```
curl http://httpApiAddress/write/test -d "this is a test" // the system will store <"test", "this is a test">
```

Please note that `httpApiAddress` can be provided on start or the default value will be used by each BFTKV node.

The returned value has no proof of correctness. DO NOT use HTTP API for any applications.

# Errors
In addition to successful results listed above, BFTKV might return an error. Possible errors and causes are listed below:

<pre>
<b>Error</b>                                             <b>Cause</b>
"insufficient number of quorum"                   There are not enough responses from servers to make a quorum
"insufficient number of signatures"               The number of signatures for the <key, value> is below threshold
"insufficient number of responses"                The number of responses from servers is below threshold
"insufficient number of valid responses"          The number of valid responses from servers is below threshold
"invalid timestamp"                               Timestamp is <code>MaxUint64</code>
"invalid signature request"                       Timestamp difference is more than <code>maxTimestampDiff</code> or less than 0
"permission denied"                               TOFU policy error
"bad timestamp"                                   Timestamp difference is more than <code>maxTimestampDiff</code> or less than previous
"equivocation error"                              Same servers signed same key and timestamp with a different value
"unknown command"                                 Unrecognized command
</pre>

