package importer

import "strings"

// GetHostname is Utils.getHostname (libs/common/src/platform/misc/utils.ts), which delegates to
// tldts 7.4.2 getHostname with default options (mixedInputs, detectIp and validateHostname on).
// Returns "" where upstream returns null.
func GetHostname(uriString string) string {
	if IsNullOrWhitespace(uriString) {
		return ""
	}
	uriString = JSTrim(uriString)
	if strings.HasPrefix(uriString, "data:") || strings.HasPrefix(uriString, "about:") || strings.HasPrefix(uriString, "file:") {
		return ""
	}
	h, ok := tldtsHostname(uriString)
	if !ok {
		return ""
	}
	return h
}

// tldtsHostname is tldts-core parseImpl(url, FLAG.HOSTNAME) with default options.
func tldtsHostname(url string) (string, bool) {
	urlIsValid := isValidHostname(url)
	h, ok := extractHostname(url, urlIsValid)
	if !ok {
		return "", false
	}
	if isIP(h) {
		return h, true
	}
	if !isValidHostname(h) {
		return "", false
	}
	return h, true
}

func isDelim(c byte) bool { return c == '/' || c == '\\' || c == '?' || c == '#' }

// specialScheme classifies url[start:colon]: 0 = not special, 1 = special, 2 = file.
func specialScheme(url string, start, colon int) int {
	switch strings.ToLower(url[start:colon]) {
	case "ws", "wss", "ftp", "http", "https":
		return 1
	case "file":
		return 2
	}
	return 0
}

func at(url string, i int) int {
	if i < 0 || i >= len(url) {
		return -1
	}
	return int(url[i])
}

func stripControl(url string) string {
	return strings.Map(func(r rune) rune {
		if r == '\t' || r == '\n' || r == '\r' {
			return -1
		}
		return r
	}, url)
}

// extractHostname is tldts-core 7.4.2 extract-hostname.ts (without the inline-validation
// optimisation, which only skips a redundant isValidHostname pass). ok=false means null.
func extractHostname(url string, urlIsValidHostname bool) (string, bool) {
	start, end := 0, len(url)
	hasUpper, isSpecial := false, false
	if !urlIsValidHostname {
		if strings.HasPrefix(url, "data:") {
			return "", false
		}
		for start < len(url) && url[start] <= 32 {
			start++
		}
		for end > start+1 && url[end-1] <= 32 {
			end--
		}
		if at(url, start) == '/' && at(url, start+1) == '/' {
			start += 2
		} else if idx := strings.Index(url[start:], ":/"); idx != -1 {
			indexOfProtocol := start + idx
			switch specialScheme(url, start, indexOfProtocol) {
			case 1:
				isSpecial = true
				start = indexOfProtocol + 2
				for at(url, start) == '/' || at(url, start) == '\\' {
					start++
				}
			case 2:
				isSpecial = true
				start = indexOfProtocol + 1
				slashes := 0
				for (at(url, start) == '/' || at(url, start) == '\\') && slashes < 2 {
					start++
					slashes++
				}
				if slashes < 2 {
					return "", false
				}
			default:
				for i := start; i < indexOfProtocol; i++ {
					c := url[i] | 32
					if !((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '.' || c == '-' || c == '+') {
						if raw := url[i]; raw == '\t' || raw == '\n' || raw == '\r' {
							return extractHostname(stripControl(url), urlIsValidHostname)
						}
						return "", false
					}
				}
				if at(url, indexOfProtocol+2) == '/' {
					start = indexOfProtocol + 3
				} else {
					return "", false
				}
			}
		} else if at(url, start) != '[' {
			indexOfColon := -1
			for i := start; i < end; i++ {
				c := url[i]
				if c == '\t' || c == '\n' || c == '\r' {
					return extractHostname(stripControl(url), urlIsValidHostname)
				}
				if c == ':' {
					indexOfColon = i
					break
				}
				if isDelim(c) {
					break
				}
			}
			if indexOfColon != -1 {
				hasIdentifier := false
				for i := indexOfColon + 1; i < end; i++ {
					c := url[i]
					if isDelim(c) {
						break
					}
					if c == '@' {
						hasIdentifier = true
						break
					}
				}
				if !hasIdentifier {
					allDigits := true
					i := indexOfColon + 1
					for ; i < end; i++ {
						c := url[i]
						if isDelim(c) {
							break
						}
						if c < '0' || c > '9' {
							allDigits = false
							break
						}
					}
					if i == indexOfColon+1 {
						allDigits = false
					}
					if !allDigits {
						special := specialScheme(url, start, indexOfColon)
						if special == 0 {
							isBareIpv6 := false
							for j := indexOfColon + 1; j < end; j++ {
								c := url[j]
								if isDelim(c) {
									break
								}
								if c == ':' {
									isBareIpv6 = true
									break
								}
							}
							if !isBareIpv6 {
								return "", false
							}
						} else {
							isSpecial = true
							start = indexOfColon + 1
							if special == 2 {
								slashes := 0
								for (at(url, start) == '/' || at(url, start) == '\\') && slashes < 2 {
									start++
									slashes++
								}
								if slashes < 2 {
									return "", false
								}
							} else {
								for at(url, start) == '/' || at(url, start) == '\\' {
									start++
								}
							}
						}
					}
				}
			}
		}

		indexOfIdentifier, indexOfClosingBracket, indexOfPort, indexOfFirstColon := -1, -1, -1, -1
		hasControl := false
		for i := start; i < end; i++ {
			c := url[i]
			if c < 64 {
				if c == '/' || c == '#' || c == '?' {
					end = i
					break
				} else if c == ':' {
					if indexOfFirstColon == -1 {
						indexOfFirstColon = i
					}
					indexOfPort = i
				} else if c == '\t' || c == '\n' || c == '\r' {
					hasControl = true
				}
			} else if isSpecial && c == '\\' {
				end = i
				break
			} else if c == '@' {
				indexOfIdentifier = i
				indexOfFirstColon = -1
			} else if c == ']' {
				indexOfClosingBracket = i
			} else if c >= 'A' && c <= 'Z' {
				hasUpper = true
			}
		}
		if hasControl {
			return extractHostname(stripControl(url), urlIsValidHostname)
		}
		if indexOfIdentifier != -1 && indexOfIdentifier >= start && indexOfIdentifier < end {
			start = indexOfIdentifier + 1
		}
		if at(url, start) == '[' {
			if indexOfClosingBracket != -1 {
				if indexOfClosingBracket < start+1 {
					return "", true
				}
				return strings.ToLower(url[start+1 : indexOfClosingBracket]), true
			}
			return "", false
		} else if indexOfPort != -1 && indexOfPort > start && indexOfPort < end && indexOfFirstColon == indexOfPort {
			end = indexOfPort
		}
		if start >= end {
			return "", false
		}
	}
	for end > start+1 && url[end-1] == '.' {
		end--
	}
	hostname := url[start:end]
	if hasUpper {
		return strings.ToLower(hostname), true
	}
	return hostname, true
}

// isValidHostname is tldts-core 7.4.2 is-valid.ts.
func isValidHostname(hostname string) bool {
	if len(hostname) > 255 || len(hostname) == 0 {
		return false
	}
	validASCII := func(c byte) bool { return (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c > 127 }
	if !validASCII(hostname[0]) && hostname[0] != '.' && hostname[0] != '_' {
		return false
	}
	lastDotIndex := -1
	lastChar := -1
	for i := 0; i < len(hostname); i++ {
		c := hostname[i]
		if c == '.' {
			if i-lastDotIndex > 64 || lastChar == '.' || lastChar == '-' {
				return false
			}
			lastDotIndex = i
		} else if !(validASCII(c) || c == '-' || c == '_') || (c == '-' && lastChar == '.') {
			return false
		}
		lastChar = int(c)
	}
	return len(hostname)-lastDotIndex-1 <= 63 && lastChar != '-'
}

// isIP is tldts-core is-ip.ts (probable IPv4 or IPv6).
func isIP(h string) bool { return isProbablyIPv6(h) || isProbablyIPv4(h) }

func isProbablyIPv4(h string) bool {
	if len(h) < 7 || len(h) > 15 {
		return false
	}
	dots := 0
	for i := 0; i < len(h); i++ {
		c := h[i]
		if c == '.' {
			dots++
		} else if c < '0' || c > '9' {
			return false
		}
	}
	return dots == 3 && h[0] != '.' && h[len(h)-1] != '.'
}

func isProbablyIPv6(h string) bool {
	if len(h) < 3 {
		return false
	}
	start, end := 0, len(h)
	if strings.HasPrefix(h, "[") {
		start = 1
	}
	if h[end-1] == ']' {
		end--
	}
	if end-start > 39 {
		return false
	}
	hasColon := false
	for ; start < end; start++ {
		c := h[start]
		if c == ':' {
			hasColon = true
		} else if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return hasColon
}
