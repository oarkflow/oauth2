package utils

import (
	"io"
	"net/http"
	"strings"
)

func ParseResponse(resp *http.Response, err error) (string, error) {
	if err != nil {
		return "", err
	}
	buf := new(strings.Builder)
	_, err = io.Copy(buf, resp.Body)
	if err != nil {
		return "", err
	}
	return buf.String(), nil
}

func HasScheme(url string) bool {
	return strings.HasPrefix(url, "http://") || strings.HasPrefix(url, "https://")
}

func AppendURL(baseURL, path string) string {
	if HasScheme(path) {
		return path
	}
	normalizedPath := strings.TrimLeft(path, "/")
	if !strings.HasSuffix(baseURL, "/") {
		baseURL += "/"
	}
	normalizedURL := baseURL + normalizedPath
	schemeEnd := strings.Index(normalizedURL, "://")
	if schemeEnd != -1 {
		scheme := normalizedURL[:schemeEnd+3]
		body := strings.ReplaceAll(normalizedURL[schemeEnd+3:], "//", "/")
		normalizedURL = scheme + body
	}
	return normalizedURL
}
