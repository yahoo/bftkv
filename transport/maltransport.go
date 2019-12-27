// Copyright 2017, Yahoo Holdings Inc.
// Licensed under the terms of the Apache license. See LICENSE file in project root for terms.

package transport

import (
	"io"
)

type MalTransportServer interface {
	MalHandler(cmd int, r io.Reader, w io.Writer) error
}
