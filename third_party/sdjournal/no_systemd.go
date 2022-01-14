// The sdjournal package exists only to target the systemd journal, which
// does not exist on Windows or MacOS.  This file exists to avoid the following
// build failure: "build constraints exclude all Go files"
package sdjournal
