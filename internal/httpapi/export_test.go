// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package httpapi

// Route is one route as New registers it, for the tests that hold
// api/openapi.yaml to the server.
type Route struct {
	Method string
	// Pattern is the path under Prefix, with the mux's placeholders.
	Pattern string
	// Device says the route speaks for a device, so it needs DeviceHeader.
	Device bool
}

// Routes lists every route New registers, in the order it registers them.
func Routes() []Route {
	var out []Route
	for _, r := range (&API{}).routes() {
		out = append(out, Route{Method: r.method, Pattern: Prefix + r.path, Device: r.need == asDevice})
	}
	return out
}
