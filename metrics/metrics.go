// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package metrics contains expvar & Prometheus types and code used by
// Tailscale for monitoring.
package metrics

import (
	"expvar"
	"fmt"
)

// Set is a string-to-Var map variable that satisfies the expvar.Var
// interface.
//
// Semantically, this is mapped by tsweb's Prometheus exporter as a
// collection of unrelated variables exported with a common prefix.
//
// This lets us have tsweb recognize *expvar.Map for different
// purposes in the future. (Or perhaps all uses of expvar.Map will
// require explicit types like this one, declaring how we want tsweb
// to export it to Prometheus.)
type Set struct {
	expvar.Map
}

// LabelMap is a string-to-Var map variable that satisfies the
// expvar.Var interface.
//
// Semantically, this is mapped by tsweb's Prometheus exporter as a
// collection of variables with the same name, with a varying label
// value. Use this to export things that are intuitively breakdowns
// into different buckets.
type LabelMap struct {
	Label string
	expvar.Map
}

// Get returns a direct pointer to the expvar.Int for key, creating it
// if necessary.
func (m *LabelMap) Get(key string) *expvar.Int {
	m.Add(key, 0)
	return m.Map.Get(key).(*expvar.Int)
}

// GetFloat returns a direct pointer to the expvar.Float for key, creating it
// if necessary.
func (m *LabelMap) GetFloat(key string) *expvar.Float {
	m.AddFloat(key, 0.0)
	return m.Map.Get(key).(*expvar.Float)
}

// CurrentFDs reports how many file descriptors are currently open.
//
// It only works on Linux. It returns zero otherwise.
func CurrentFDs() int {
	return currentFDs()
}

// Distribution represents a set of values separated into individual "bins".
//
// Semantically, this is mapped by tsweb's Prometheus exporter as a collection
// of variables with the same name and the "le" ("less than or equal") label,
// one per bin. For example, with Bins=[1,2,10], the Prometheus variables will
// be:
//    myvar_here{le="1"}	12
//    myvar_here{le="2"}	34
//    myvar_here{le="10"}	56
//    myvar_here{le="inf"}	78
//
// Additionally, a "_max", "_min" and "_count" variable will be added
// containing the observed maximum, minimum, and total count of samples:
//    myvar_here_max	99
//    myvar_here_min	0
//    myvar_here_count	180
type Distribution struct {
	expvar.Map
	Bins []float64
}

func (d *Distribution) Init() {
	// Initialze all values to zero
	for _, bin := range d.Bins {
		d.Map.Add(fmt.Sprint(bin), 0)
	}
	d.Map.Add("Inf", 0)
	d.Map.Add("count", 0)
	d.Map.AddFloat("min", 0.0)
	d.Map.AddFloat("max", 0.0)
}

func (d *Distribution) AddFloat(val float64) {
	label := "Inf"
	for _, bin := range d.Bins {
		if val <= bin {
			label = fmt.Sprint(bin)
			break
		}
	}

	d.Map.Add(label, 1)
	d.Map.Add("count", 1)

	min, ok := d.Map.Get("min").(*expvar.Float)
	if ok {
		if min.Value() > val {
			min.Set(val)
		}
	} else {
		min = new(expvar.Float)
		min.Set(val)
		d.Map.Set("min", min)
	}

	max, ok := d.Map.Get("max").(*expvar.Float)
	if ok {
		if max.Value() < val {
			max.Set(val)
		}
	} else {
		max = new(expvar.Float)
		max.Set(val)
		d.Map.Set("max", max)
	}
}
