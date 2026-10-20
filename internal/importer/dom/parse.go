package dom

import (
	"encoding/xml"
	"errors"
	"fmt"
	"html"
	"io"
	"strings"
)

// ParseXML parses a well-formed XML document. Any well-formedness error (mismatched tags,
// undefined entities, missing or multiple root elements, text outside the root) is returned as an
// error, matching DOMParser producing a <parsererror> document. The encoding declaration is
// ignored because the input is already a decoded string.
func ParseXML(data string) (*Node, error) {
	data = strings.TrimPrefix(data, "\ufeff") // XML parsers skip a leading byte order mark
	d := xml.NewDecoder(strings.NewReader(data))
	d.Strict = true
	d.CharsetReader = func(_ string, input io.Reader) (io.Reader, error) { return input, nil }

	doc := &Node{Type: DocumentNode}
	cur := doc
	roots := 0
	for {
		tok, err := d.RawToken()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		switch t := tok.(type) {
		case xml.StartElement:
			if cur == doc {
				roots++
				if roots > 1 {
					return nil, errors.New("xml: multiple root elements")
				}
			}
			el := &Node{Type: ElementNode, Name: qname(t.Name)}
			for _, a := range t.Attr {
				el.Attrs = append(el.Attrs, Attr{Name: qname(a.Name), Value: a.Value})
			}
			cur.appendChild(el)
			cur = el
		case xml.EndElement:
			if cur == doc || cur.Name != qname(t.Name) {
				return nil, fmt.Errorf("xml: unexpected end element </%s>", qname(t.Name))
			}
			cur = cur.Parent
		case xml.CharData:
			if cur == doc {
				if strings.TrimSpace(string(t)) != "" {
					return nil, errors.New("xml: text outside the root element")
				}
				continue
			}
			cur.appendText(string(t))
		case xml.Comment:
			cur.appendChild(&Node{Type: CommentNode, Data: string(t)})
		}
	}
	if cur != doc {
		return nil, fmt.Errorf("xml: unclosed element <%s>", cur.Name)
	}
	if roots == 0 {
		return nil, errors.New("xml: no root element")
	}
	return doc, nil
}

func qname(n xml.Name) string {
	if n.Space != "" {
		return n.Space + ":" + n.Local
	}
	return n.Local
}

var voidElements = map[string]bool{
	"area": true, "base": true, "br": true, "col": true, "embed": true, "hr": true, "img": true,
	"input": true, "link": true, "meta": true, "param": true, "source": true, "track": true,
	"wbr": true,
}

var blockClosesP = map[string]bool{
	"address": true, "article": true, "aside": true, "blockquote": true, "div": true, "dl": true,
	"fieldset": true, "footer": true, "form": true, "h1": true, "h2": true, "h3": true, "h4": true,
	"h5": true, "h6": true, "header": true, "hr": true, "menu": true, "nav": true, "ol": true,
	"p": true, "pre": true, "section": true, "table": true, "ul": true,
}

// implied end tags: opening `key` closes an open element in the value set (if it is current).
var impliedEnd = map[string]map[string]bool{
	"li":     {"li": true},
	"dt":     {"dt": true, "dd": true},
	"dd":     {"dt": true, "dd": true},
	"tr":     {"tr": true, "td": true, "th": true},
	"td":     {"td": true, "th": true},
	"th":     {"td": true, "th": true},
	"option": {"option": true},
}

// ParseHTML parses an HTML document leniently. It never fails.
func ParseHTML(data string) *Node {
	doc := &Node{Type: DocumentNode, html: true}
	cur := doc
	i := 0
	n := len(data)
	text := func(s string) {
		cur.appendText(html.UnescapeString(s))
	}
	for i < n {
		lt := strings.IndexByte(data[i:], '<')
		if lt < 0 {
			text(data[i:])
			break
		}
		text(data[i : i+lt])
		i += lt
		rest := data[i:]
		switch {
		case strings.HasPrefix(rest, "<!--"):
			end := strings.Index(rest[4:], "-->")
			if end < 0 {
				cur.appendChild(&Node{Type: CommentNode, Data: rest[4:]})
				i = n
			} else {
				cur.appendChild(&Node{Type: CommentNode, Data: rest[4 : 4+end]})
				i += 4 + end + 3
			}
		case strings.HasPrefix(rest, "<!") || strings.HasPrefix(rest, "<?"):
			end := strings.IndexByte(rest, '>')
			if end < 0 {
				i = n
			} else {
				i += end + 1
			}
		case strings.HasPrefix(rest, "</") && len(rest) > 2 && isNameStart(rest[2]):
			j := 2
			for j < len(rest) && !isSpaceOrEnd(rest[j]) {
				j++
			}
			name := strings.ToLower(rest[2:j])
			end := strings.IndexByte(rest, '>')
			if end < 0 {
				i = n
			} else {
				i += end + 1
			}
			for x := cur; x != doc; x = x.Parent {
				if x.Name == name {
					cur = x.Parent
					break
				}
			}
		case len(rest) > 1 && isNameStart(rest[1]):
			el, consumed, selfClose := parseStartTag(rest)
			i += consumed
			if closes, ok := impliedEnd[el.Name]; ok && cur.Type == ElementNode && closes[cur.Name] {
				cur = cur.Parent
			}
			if blockClosesP[el.Name] && cur.Type == ElementNode && cur.Name == "p" {
				cur = cur.Parent
			}
			cur.appendChild(el)
			if selfClose || voidElements[el.Name] {
				continue
			}
			switch el.Name {
			case "script", "style", "textarea", "title":
				body, used := rawTextUntil(data[i:], el.Name)
				if el.Name == "textarea" || el.Name == "title" {
					el.appendText(html.UnescapeString(body))
				} else {
					el.appendText(body)
				}
				i += used
			default:
				cur = el
			}
		default:
			text("<")
			i++
		}
	}
	return doc
}

func isNameStart(c byte) bool { return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') }

func isSpace(c byte) bool { return c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\f' }

func isSpaceOrEnd(c byte) bool { return isSpace(c) || c == '>' || c == '/' }

// parseStartTag parses "<name attr=...>" at the start of s.
func parseStartTag(s string) (el *Node, consumed int, selfClose bool) {
	j := 1
	for j < len(s) && !isSpaceOrEnd(s[j]) {
		j++
	}
	el = &Node{Type: ElementNode, Name: strings.ToLower(s[1:j])}
	for j < len(s) {
		for j < len(s) && (isSpace(s[j]) || s[j] == '/') {
			if s[j] == '/' && j+1 < len(s) && s[j+1] == '>' {
				return el, j + 2, true
			}
			j++
		}
		if j >= len(s) {
			break
		}
		if s[j] == '>' {
			return el, j + 1, false
		}
		k := j
		for k < len(s) && !isSpace(s[k]) && s[k] != '=' && s[k] != '>' && !(s[k] == '/' && k+1 < len(s) && s[k+1] == '>') {
			k++
		}
		name := strings.ToLower(s[j:k])
		j = k
		for j < len(s) && isSpace(s[j]) {
			j++
		}
		val := ""
		if j < len(s) && s[j] == '=' {
			j++
			for j < len(s) && isSpace(s[j]) {
				j++
			}
			if j < len(s) && (s[j] == '"' || s[j] == '\'') {
				q := s[j]
				end := strings.IndexByte(s[j+1:], q)
				if end < 0 {
					val = s[j+1:]
					j = len(s)
				} else {
					val = s[j+1 : j+1+end]
					j += end + 2
				}
			} else {
				k := j
				for k < len(s) && !isSpace(s[k]) && s[k] != '>' {
					k++
				}
				val = s[j:k]
				j = k
			}
		}
		if name != "" && !el.HasAttribute(name) {
			el.Attrs = append(el.Attrs, Attr{Name: name, Value: html.UnescapeString(val)})
		}
	}
	return el, len(s), false
}

// rawTextUntil returns the text before the matching end tag and the bytes consumed (including the
// end tag).
func rawTextUntil(s, name string) (string, int) {
	lower := strings.ToLower(s)
	needle := "</" + name
	from := 0
	for {
		idx := strings.Index(lower[from:], needle)
		if idx < 0 {
			return s, len(s)
		}
		idx += from
		after := idx + len(needle)
		if after >= len(s) || isSpaceOrEnd(s[after]) {
			end := strings.IndexByte(s[after:], '>')
			if end < 0 {
				return s[:idx], len(s)
			}
			return s[:idx], after + end + 1
		}
		from = after
	}
}
