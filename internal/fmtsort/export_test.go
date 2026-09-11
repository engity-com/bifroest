// Copyright 2018 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSES/BSD-3-Clause.txt file.
// SPDX-License-Identifier: BSD-3-Clause

package fmtsort

import "reflect"

func Compare(a, b reflect.Value) int {
	return compare(a, b)
}
