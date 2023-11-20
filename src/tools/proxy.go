package tools

import (
	"bytes"
	"compress/gzip"
	"fmt"
	"hash/crc32"
	"io"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
)

var originalUrlResolver = make(map[string]*url.URL)
var mutex = &sync.Mutex{}
var cachePath = getEnv("CACHE_PATH", "./cache")

// ProxyRequestHandler intercepts requests to CodeArtifact and add the Authorization header + correct Host header
func ProxyRequestHandler(p *httputil.ReverseProxy) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		mutex.Lock()
		// Store the original host header for each request
		originalUrlResolver[r.RemoteAddr] = r.URL
		originalUrlResolver[r.RemoteAddr].Host = r.Host
		originalUrlResolver[r.RemoteAddr].Scheme = r.URL.Scheme

		if r.Header.Get("X-Forwarded-Proto") == "https" {
			originalUrlResolver[r.RemoteAddr].Scheme = "https"
		} else {
			originalUrlResolver[r.RemoteAddr].Scheme = "http"
		}

		// Override the Host header with the CodeArtifact Host
		u, _ := url.Parse(CodeArtifactAuthInfo.Url)
		r.Host = u.Host

		// Set the Authorization header with the CodeArtifact Authorization Token
		r.SetBasicAuth("aws", CodeArtifactAuthInfo.AuthorizationToken)

		hash := HashStrings([]string{r.URL.RequestURI()})

		// Check if the request is for a tarball, if so, check if we have a cached version
		if strings.HasSuffix(r.URL.RequestURI(), ".tgz") {
			// Check if the file exists in the cache
			if _, err := os.Stat(fmt.Sprintf("%s/%s", cachePath, hash)); err == nil {
				log.Printf("Serving cached version of %s", r.URL.RequestURI())
				http.ServeFile(w, r, fmt.Sprintf("%s/%s", cachePath, hash))
				mutex.Unlock()
				return
			}
		}

		log.Printf("REQ Method: %s; URI: %s; hash: %s", r.Method, r.URL.RequestURI(), hash)

		log.Printf("Sending request to %s%s", strings.Trim(CodeArtifactAuthInfo.Url, "/"), r.URL.RequestURI())
		mutex.Unlock()

		p.ServeHTTP(w, r)
	}
}

// Handles the response back to the client once intercepted from CodeArtifact
func ProxyResponseHandler() func(*http.Response) error {
	return func(r *http.Response) error {
		log.Printf("Received %d response from %s", r.StatusCode, r.Request.URL.String())
		log.Printf("RES: %s \"%s\" %d \"%s\" \"%s\"", r.Request.RemoteAddr, r.Request.Method, r.StatusCode, r.Request.RequestURI, r.Request.UserAgent())

		contentType := r.Header.Get("Content-Type")

		mutex.Lock()
		originalUrl := originalUrlResolver[r.Request.RemoteAddr]
		delete(originalUrlResolver, r.Request.RemoteAddr)

		u, _ := url.Parse(CodeArtifactAuthInfo.Url)
		hostname := u.Host + ":443"
		mutex.Unlock()

		// Rewrite the 301 to point from CodeArtifact URL to the proxy instead..
		if r.StatusCode == 301 || r.StatusCode == 302 {
			location, _ := r.Location()

			hash := HashStrings([]string{r.Request.RequestURI})

			//log.Printf("RequestURI: %s; Hash: %s; Location: %s\n", r.Request.RequestURI, hash, location)
			// Download the file and cache it
			if strings.HasSuffix(r.Request.RequestURI, ".tgz") {
				log.Printf("Caching %s", r.Request.RequestURI)
				// Download the file and cache it
				resp, err := http.Get(location.String())
				if err != nil {
					log.Printf("Error downloading file: %s", err)
				}

				defer resp.Body.Close()

				body, err := io.ReadAll(resp.Body)
				if err != nil {
					log.Printf("Error reading response body: %s", err)
				}

				err = os.WriteFile(fmt.Sprintf("%s/%s", cachePath, hash), body, 0644)
				if err != nil {
					log.Printf("Error writing file to cache: %s", err)
				}
			}

			// Only attempt to rewrite the location if the host matches the CodeArtifact host
			// Otherwise leave the original location intact (e.g a redirect to a S3 presigned URL)
			if location.Host == u.Host {
				location.Host = originalUrl.Host
				location.Scheme = originalUrl.Scheme
				location.Path = strings.Replace(location.Path, u.Path, "", 1)
			}
		}

		// Do some quick fixes to the HTTP response for NPM install requests
		// Also support for pnpm and bun
		if strings.HasPrefix(r.Request.UserAgent(), "npm") ||
			strings.HasPrefix(r.Request.UserAgent(), "pnpm") ||
			strings.HasPrefix(r.Request.UserAgent(), "Bun") {

			// Respond to only requests that respond with JSON
			// There might eventually be additional headers i don't know about?
			if !strings.Contains(contentType, "application/json") && !strings.Contains(contentType, "application/vnd.npm.install-v1+json") {
				return nil
			}

			var body io.ReadCloser

			if r.Header.Get("Content-Encoding") == "gzip" {
				body, _ = gzip.NewReader(r.Body)
				r.Header.Del("Content-Encoding")
			} else {
				body = r.Body
			}

			// replace any instances of the CodeArtifact URL with the local URL
			oldContentResponse, _ := io.ReadAll(body)
			oldContentResponseStr := string(oldContentResponse)

			mutex.Lock()
			resolvedHostname := strings.Replace(CodeArtifactAuthInfo.Url, u.Host, hostname, -1)
			newUrl := fmt.Sprintf("%s://%s/", originalUrl.Scheme, originalUrl.Host)

			newResponseContent := strings.Replace(oldContentResponseStr, resolvedHostname, newUrl, -1)
			newResponseContent = strings.Replace(newResponseContent, CodeArtifactAuthInfo.Url, newUrl, -1)
			mutex.Unlock()

			r.Body = io.NopCloser(strings.NewReader(newResponseContent))
			r.ContentLength = int64(len(newResponseContent))
			r.Header.Set("Content-Length", strconv.Itoa(len(newResponseContent)))
		}

		return nil
	}

}

func EmptyHandler(w http.ResponseWriter, r *http.Request) {
	//log.Printf("REQ: %s %s \"%s\" \"%s\"", r.RemoteAddr, r.Method, r.URL.RequestURI(), r.UserAgent())
	//log.Printf("RES: %s \"%s\" %d \"%s\" \"%s\"", r.RemoteAddr, r.Method, 200, r.URL.RequestURI(), r.UserAgent())

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(200)
	w.Write([]byte(`{"actions": []}`))
}

// ProxyInit initialises the CodeArtifact proxy and starts the HTTP listener
func ProxyInit() {
	remote, err := url.Parse(CodeArtifactAuthInfo.Url)
	if err != nil {
		panic(err)
	}

	// Get port from LISTEN_PORT environment variable. If not set, default to 8080.
	port := getEnv("LISTEN_PORT", "8080")

	proxy := httputil.NewSingleHostReverseProxy(remote)

	proxy.ModifyResponse = ProxyResponseHandler()

	http.HandleFunc("/", ProxyRequestHandler(proxy))
	http.HandleFunc("/-/npm/v1/security/audits/quick", EmptyHandler)
	http.HandleFunc("/-/npm/v1/security/advisories/bulk", EmptyHandler)

	err = http.ListenAndServe(":"+port, nil)
	if err != nil {
		panic(err)
	}
}

func getEnv(key, fallback string) string {
	if value, ok := os.LookupEnv(key); ok {
		return value
	}
	return fallback
}

// String hashes a string to a unique hashcode.
//
// crc32 returns a uint32, but for our use we need
// and non negative integer. Here we cast to an integer
// and invert it if the result is negative.
func HashString(s string) int {
	v := int(crc32.ChecksumIEEE([]byte(s)))
	if v >= 0 {
		return v
	}
	if -v >= 0 {
		return -v
	}
	// v == MinInt
	return 0
}

// Strings hashes a list of strings to a unique hashcode.
func HashStrings(strings []string) string {
	var buf bytes.Buffer

	for _, s := range strings {
		buf.WriteString(fmt.Sprintf("%s-", s))
	}

	return fmt.Sprintf("%d", HashString(buf.String()))
}
