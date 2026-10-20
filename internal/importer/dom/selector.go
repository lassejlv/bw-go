package dom

import (
	"fmt"
	"strings"
	"sync"
)

// Selector is a compiled CSS selector list. Supported syntax (everything the importers need, and
// a little more):
//
//	type selectors (`Group`, `*`; matched against the local name, case-insensitively in HTML)
//	#id, .class
//	[attr] [attr=v] [attr="v"] [attr='v'] [attr~=v] [attr^=v] [attr$=v] [attr*=v] [attr|=v]
//	combinators: descendant (whitespace), child (>), adjacent sibling (+), general sibling (~)
//	selector lists separated by commas
//
// Pseudo-classes are not supported.
type Selector struct {
	alts []complexSel
}

type combinator byte

const (
	combNone       combinator = 0
	combDescendant combinator = ' '
	combChild      combinator = '>'
	combAdjacent   combinator = '+'
	combSibling    combinator = '~'
)

type attrSel struct {
	name, op, value string
}

type compound struct {
	tag   string // "" or "*" = any
	id    string
	class []string
	attrs []attrSel
}

// complexSel stores compounds right-to-left: parts[0] is the subject; combs[i] links parts[i] to
// parts[i+1] (parts[i+1] is the ancestor/sibling).
type complexSel struct {
	parts []compound
	combs []combinator
}

var cache sync.Map

// MustCompile compiles a selector (cached) and panics on syntax errors.
func MustCompile(s string) *Selector {
	if v, ok := cache.Load(s); ok {
		return v.(*Selector)
	}
	sel, err := Compile(s)
	if err != nil {
		panic(err)
	}
	cache.Store(s, sel)
	return sel
}

// Compile parses a selector list.
func Compile(s string) (*Selector, error) {
	p := &selParser{s: s}
	sel := &Selector{}
	for {
		c, err := p.complex()
		if err != nil {
			return nil, err
		}
		sel.alts = append(sel.alts, c)
		p.skipSpace()
		if p.i >= len(p.s) {
			break
		}
		if p.s[p.i] != ',' {
			return nil, fmt.Errorf("dom: invalid selector %q at %d", s, p.i)
		}
		p.i++
	}
	return sel, nil
}

type selParser struct {
	s string
	i int
}

func (p *selParser) skipSpace() bool {
	start := p.i
	for p.i < len(p.s) && isSpace(p.s[p.i]) {
		p.i++
	}
	return p.i > start
}

func (p *selParser) complex() (complexSel, error) {
	var parts []compound
	var combs []combinator
	p.skipSpace()
	for {
		c, err := p.compound()
		if err != nil {
			return complexSel{}, err
		}
		parts = append(parts, c)
		hadSpace := p.skipSpace()
		if p.i >= len(p.s) || p.s[p.i] == ',' {
			break
		}
		comb := combDescendant
		switch p.s[p.i] {
		case '>', '+', '~':
			comb = combinator(p.s[p.i])
			p.i++
			p.skipSpace()
		default:
			if !hadSpace {
				return complexSel{}, fmt.Errorf("dom: invalid selector %q at %d", p.s, p.i)
			}
		}
		combs = append(combs, comb)
	}
	// reverse to right-to-left
	for l, r := 0, len(parts)-1; l < r; l, r = l+1, r-1 {
		parts[l], parts[r] = parts[r], parts[l]
	}
	for l, r := 0, len(combs)-1; l < r; l, r = l+1, r-1 {
		combs[l], combs[r] = combs[r], combs[l]
	}
	return complexSel{parts: parts, combs: combs}, nil
}

func isIdentChar(c byte) bool {
	return c == '-' || c == '_' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c >= 0x80 || c == '\\'
}

func (p *selParser) ident() string {
	var b strings.Builder
	for p.i < len(p.s) && isIdentChar(p.s[p.i]) {
		if p.s[p.i] == '\\' && p.i+1 < len(p.s) {
			p.i++
		}
		b.WriteByte(p.s[p.i])
		p.i++
	}
	return b.String()
}

func (p *selParser) compound() (compound, error) {
	var c compound
	start := p.i
	if p.i < len(p.s) && p.s[p.i] == '*' {
		c.tag = "*"
		p.i++
	} else {
		c.tag = p.ident()
		// Allow namespace-prefixed type selectors written as `ns|tag` by ignoring the prefix.
		if p.i < len(p.s) && p.s[p.i] == '|' && (p.i+1 >= len(p.s) || p.s[p.i+1] != '=') {
			p.i++
			c.tag = p.ident()
		}
	}
	for p.i < len(p.s) {
		switch p.s[p.i] {
		case '#':
			p.i++
			c.id = p.ident()
		case '.':
			p.i++
			c.class = append(c.class, p.ident())
		case '[':
			p.i++
			p.skipSpace()
			a := attrSel{name: p.ident()}
			p.skipSpace()
			if p.i < len(p.s) && p.s[p.i] != ']' {
				if strings.ContainsRune("~^$*|", rune(p.s[p.i])) {
					a.op = string(p.s[p.i])
					p.i++
				}
				if p.i >= len(p.s) || p.s[p.i] != '=' {
					return c, fmt.Errorf("dom: invalid attribute selector in %q", p.s)
				}
				a.op += "="
				p.i++
				p.skipSpace()
				if p.i < len(p.s) && (p.s[p.i] == '"' || p.s[p.i] == '\'') {
					q := p.s[p.i]
					end := strings.IndexByte(p.s[p.i+1:], q)
					if end < 0 {
						return c, fmt.Errorf("dom: unterminated string in %q", p.s)
					}
					a.value = p.s[p.i+1 : p.i+1+end]
					p.i += end + 2
				} else {
					a.value = p.ident()
				}
				p.skipSpace()
			}
			if p.i >= len(p.s) || p.s[p.i] != ']' {
				return c, fmt.Errorf("dom: invalid attribute selector in %q", p.s)
			}
			p.i++
			c.attrs = append(c.attrs, a)
		case ':':
			return c, fmt.Errorf("dom: pseudo-classes are not supported: %q", p.s)
		default:
			goto done
		}
	}
done:
	if p.i == start {
		return c, fmt.Errorf("dom: invalid selector %q at %d", p.s, p.i)
	}
	return c, nil
}

// Match reports whether element e matches the selector.
func (s *Selector) Match(e *Node) bool {
	if e == nil || e.Type != ElementNode {
		return false
	}
	for _, alt := range s.alts {
		if alt.match(e, 0) {
			return true
		}
	}
	return false
}

func (c complexSel) match(e *Node, idx int) bool {
	if !c.parts[idx].match(e) {
		return false
	}
	if idx == len(c.parts)-1 {
		return true
	}
	switch c.combs[idx] {
	case combChild:
		p := e.Parent
		return p != nil && p.Type == ElementNode && c.match(p, idx+1)
	case combDescendant:
		for p := e.Parent; p != nil && p.Type == ElementNode; p = p.Parent {
			if c.match(p, idx+1) {
				return true
			}
		}
		return false
	case combAdjacent:
		prev := prevElementSibling(e)
		return prev != nil && c.match(prev, idx+1)
	case combSibling:
		for prev := prevElementSibling(e); prev != nil; prev = prevElementSibling(prev) {
			if c.match(prev, idx+1) {
				return true
			}
		}
		return false
	}
	return false
}

func prevElementSibling(e *Node) *Node {
	if e.Parent == nil {
		return nil
	}
	var prev *Node
	for _, c := range e.Parent.ChildNodes {
		if c == e {
			return prev
		}
		if c.Type == ElementNode {
			prev = c
		}
	}
	return nil
}

func (c compound) match(e *Node) bool {
	if c.tag != "" && c.tag != "*" {
		if e.html {
			if !strings.EqualFold(e.LocalName(), c.tag) {
				return false
			}
		} else if e.LocalName() != c.tag {
			return false
		}
	}
	if c.id != "" && e.Attr("id") != c.id {
		return false
	}
	for _, cl := range c.class {
		if !containsWord(e.Attr("class"), cl) {
			return false
		}
	}
	for _, a := range c.attrs {
		v, ok := e.GetAttribute(a.name)
		if !ok {
			return false
		}
		switch a.op {
		case "":
		case "=":
			if v != a.value {
				return false
			}
		case "~=":
			if !containsWord(v, a.value) {
				return false
			}
		case "^=":
			if a.value == "" || !strings.HasPrefix(v, a.value) {
				return false
			}
		case "$=":
			if a.value == "" || !strings.HasSuffix(v, a.value) {
				return false
			}
		case "*=":
			if a.value == "" || !strings.Contains(v, a.value) {
				return false
			}
		case "|=":
			if v != a.value && !strings.HasPrefix(v, a.value+"-") {
				return false
			}
		}
	}
	return true
}

func containsWord(list, w string) bool {
	for _, f := range strings.Fields(list) {
		if f == w {
			return true
		}
	}
	return false
}
