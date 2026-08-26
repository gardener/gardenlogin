/*
SPDX-FileCopyrightText: Contributors to the Gardener project

SPDX-License-Identifier: Apache-2.0
*/

package util

import "time"

// Clock provides the current time.
type Clock interface {
	// Now returns the current time.
	Now() time.Time
}

// RealClock implements Clock interface.
type RealClock struct{}

// Now returns the current time.
func (RealClock) Now() time.Time {
	return time.Now()
}
