// Package dom is a tiny DOM for the XML/HTML importers: it parses documents into a node tree and
// supports the subset of the browser DOM API the TypeScript importers use (querySelector,
// querySelectorAll, textContent, getAttribute, attributes, tagName, children, parentNode).
//
// XML is parsed strictly (like DOMParser with "application/xml": malformed input is an error and
// the importer gets `null`). HTML is parsed leniently (like "text/html"): tag and attribute names
// are lower-cased, entities are decoded, void elements and a few implied end tags are handled.
package dom

import (
	"strings"
)

// NodeType distinguishes node kinds.
type NodeType int

const (
	DocumentNode NodeType = iota
	ElementNode
	TextNode
	CommentNode
)

// Attr is one attribute (name as written in the source; lower-cased for HTML).
type Attr struct {
	Name  string
	Value string
}

// Node is a document, element, text or comment node.
type Node struct {
	Type NodeType
	// Name is the qualified tag name for elements ("prefix:local" in XML, lower-case in HTML).
	Name string
	// Data is the text of text and comment nodes.
	Data       string
	Attrs      []Attr
	Parent     *Node
	ChildNodes []*Node
	html       bool
}

// TagName returns the element's qualified name (Element.tagName; HTML names are returned
// lower-case here, unlike browsers which upper-case them).
func (n *Node) TagName() string { return n.Name }

// LocalName returns the tag name without a namespace prefix.
func (n *Node) LocalName() string {
	if i := strings.IndexByte(n.Name, ':'); i >= 0 {
		return n.Name[i+1:]
	}
	return n.Name
}

// IsHTML reports whether the node belongs to an HTML document.
func (n *Node) IsHTML() bool { return n.html }

// Children returns the element children (Element.children).
func (n *Node) Children() []*Node {
	var out []*Node
	for _, c := range n.ChildNodes {
		if c.Type == ElementNode {
			out = append(out, c)
		}
	}
	return out
}

// FirstElementChild returns the first element child or nil.
func (n *Node) FirstElementChild() *Node {
	for _, c := range n.ChildNodes {
		if c.Type == ElementNode {
			return c
		}
	}
	return nil
}

// DocumentElement returns the root element of a document node (or nil).
func (n *Node) DocumentElement() *Node { return n.FirstElementChild() }

// TextContent concatenates all descendant text (Node.textContent). Comments are skipped.
func (n *Node) TextContent() string {
	if n == nil {
		return ""
	}
	switch n.Type {
	case TextNode, CommentNode:
		return n.Data
	}
	var b strings.Builder
	var walk func(*Node)
	walk = func(x *Node) {
		for _, c := range x.ChildNodes {
			switch c.Type {
			case TextNode:
				b.WriteString(c.Data)
			case ElementNode:
				walk(c)
			}
		}
	}
	walk(n)
	return b.String()
}

func (n *Node) attrKey(name string) string {
	if n.html {
		return strings.ToLower(name)
	}
	return name
}

// GetAttribute returns the attribute value and whether it exists (getAttribute returning null).
func (n *Node) GetAttribute(name string) (string, bool) {
	if n == nil {
		return "", false
	}
	name = n.attrKey(name)
	for _, a := range n.Attrs {
		if a.Name == name {
			return a.Value, true
		}
	}
	return "", false
}

// Attr returns the attribute value or "" when missing.
func (n *Node) Attr(name string) string {
	v, _ := n.GetAttribute(name)
	return v
}

// HasAttribute reports whether the attribute exists.
func (n *Node) HasAttribute(name string) bool {
	_, ok := n.GetAttribute(name)
	return ok
}

// QuerySelector returns the first descendant (document order) matching the CSS selector, or nil.
// The selector is matched against the whole document, as in the DOM. Invalid selectors panic
// (they are programming errors, like the SyntaxError a browser throws).
func (n *Node) QuerySelector(selector string) *Node {
	if n == nil {
		return nil
	}
	sel := MustCompile(selector)
	var found *Node
	n.walkDescendants(func(e *Node) bool {
		if sel.Match(e) {
			found = e
			return false
		}
		return true
	})
	return found
}

// QuerySelectorAll returns every descendant matching the selector, in document order.
func (n *Node) QuerySelectorAll(selector string) []*Node {
	if n == nil {
		return nil
	}
	sel := MustCompile(selector)
	var out []*Node
	n.walkDescendants(func(e *Node) bool {
		if sel.Match(e) {
			out = append(out, e)
		}
		return true
	})
	return out
}

// QuerySelectorDirectChild returns the first child element of n that matches selector
// (BaseImporter.querySelectorDirectChild).
func (n *Node) QuerySelectorDirectChild(selector string) *Node {
	all := n.QuerySelectorAllDirectChild(selector)
	if len(all) == 0 {
		return nil
	}
	return all[0]
}

// QuerySelectorAllDirectChild returns the child elements of n that match selector
// (BaseImporter.querySelectorAllDirectChild).
func (n *Node) QuerySelectorAllDirectChild(selector string) []*Node {
	var out []*Node
	for _, e := range n.QuerySelectorAll(selector) {
		if e.Parent == n {
			out = append(out, e)
		}
	}
	return out
}

// walkDescendants visits element descendants in document order until fn returns false.
func (n *Node) walkDescendants(fn func(*Node) bool) bool {
	for _, c := range n.ChildNodes {
		if c.Type != ElementNode {
			continue
		}
		if !fn(c) {
			return false
		}
		if !c.walkDescendants(fn) {
			return false
		}
	}
	return true
}

func (n *Node) appendChild(c *Node) {
	c.Parent = n
	c.html = n.html
	n.ChildNodes = append(n.ChildNodes, c)
}

func (n *Node) appendText(s string) {
	if s == "" {
		return
	}
	if l := len(n.ChildNodes); l > 0 && n.ChildNodes[l-1].Type == TextNode {
		n.ChildNodes[l-1].Data += s
		return
	}
	n.appendChild(&Node{Type: TextNode, Data: s})
}
