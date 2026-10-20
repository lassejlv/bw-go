package keepasskdbx

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"io"
	"strconv"
	"strings"
)

// The decrypted database, reduced to what the SDK importer reads.

type database struct {
	root              *group
	recycleBinEnabled *bool
	recycleBinUUID    *[16]byte
}

type group struct {
	uuid    [16]byte
	name    string
	entries []*entry
	groups  []*group
}

// entry keeps the string fields in file order (the crate uses a HashMap, so upstream's custom field
// order is unspecified); a repeated key keeps its first position and its last value.
type entry struct {
	keys   []string
	values map[string]fieldValue
}

type fieldValue struct {
	value     string
	protected bool
}

func newEntry() *entry { return &entry{values: map[string]fieldValue{}} }

func (e *entry) set(key, value string, protected bool) {
	if _, ok := e.values[key]; !ok {
		e.keys = append(e.keys, key)
	}
	e.values[key] = fieldValue{value: value, protected: protected}
}

// get is Entry::get: the field's value, or ok=false when the entry has no such field.
func (e *entry) get(key string) (string, bool) {
	v, ok := e.values[key]
	return v.value, ok
}

// --- XML tree ---------------------------------------------------------------------------------

type xnode struct {
	name     string
	attrs    map[string]string
	text     strings.Builder
	children []*xnode
}

func (n *xnode) child(name string) *xnode {
	for _, c := range n.children {
		if c.name == name {
			return c
		}
	}
	return nil
}

func (n *xnode) attr(name string) (string, bool) {
	v, ok := n.attrs[name]
	return v, ok
}

// parseXMLTree parses the inner XML document (quick-xml: UTF-8 assumed, declared encoding ignored,
// end tags must match).
func parseXMLTree(data []byte) (*xnode, error) {
	data = bytes.TrimPrefix(data, []byte("\xEF\xBB\xBF"))
	dec := xml.NewDecoder(bytes.NewReader(data))
	dec.Strict = true
	dec.CharsetReader = func(_ string, r io.Reader) (io.Reader, error) { return r, nil }
	var stack []*xnode
	var root *xnode
	for {
		tok, err := dec.RawToken()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, errFormat("error parsing XML inside KDBX: " + err.Error())
		}
		switch t := tok.(type) {
		case xml.StartElement:
			n := &xnode{name: qualified(t.Name), attrs: map[string]string{}}
			for _, a := range t.Attr {
				n.attrs[qualified(a.Name)] = a.Value
			}
			if len(stack) > 0 {
				p := stack[len(stack)-1]
				p.children = append(p.children, n)
			} else if root == nil {
				root = n
			}
			stack = append(stack, n)
		case xml.EndElement:
			if len(stack) == 0 || stack[len(stack)-1].name != qualified(t.Name) {
				return nil, errFormat("error parsing XML inside KDBX: mismatched end tag")
			}
			stack = stack[:len(stack)-1]
		case xml.CharData:
			if len(stack) > 0 {
				stack[len(stack)-1].text.Write(t)
			}
		}
	}
	if root == nil || len(stack) != 0 {
		return nil, errFormat("error parsing XML inside KDBX: unexpected end of document")
	}
	return root, nil
}

// --- Value decoders (custom_serde.rs) ---------------------------------------------------------

// parseOptBool is cs_opt_bool.
func parseOptBool(s string) (*bool, error) {
	if strings.TrimSpace(s) == "" {
		return nil, nil
	}
	switch strings.ToLower(s) {
	case "true", "1":
		v := true
		return &v, nil
	case "false", "0":
		v := false
		return &v, nil
	case "null":
		return nil, nil
	}
	return nil, errFormat("error parsing XML inside KDBX: invalid boolean string: " + s)
}

// parseBool is cs_bool.
func parseBool(s string) (bool, error) {
	switch strings.ToLower(s) {
	case "true", "1":
		return true, nil
	case "false", "0":
		return false, nil
	}
	return false, errFormat("error parsing XML inside KDBX: invalid boolean string: " + s)
}

// parseUUID is the UUID deserializer (base64 of 16 bytes).
func parseUUID(s string) ([16]byte, error) {
	var u [16]byte
	b, ok := decodeBase64Strict(s)
	if !ok || len(b) != 16 {
		return u, errFormat("error parsing XML inside KDBX: invalid UUID")
	}
	copy(u[:], b)
	return u, nil
}

// --- KeePassFile → database (xml_db/mod.rs, group.rs, entry.rs, meta.rs) ----------------------

type xmlLoader struct {
	inner   innerStream
	groups  map[[16]byte]bool
	entries map[[16]byte]bool
}

func parseXMLDatabase(data []byte, inner innerStream) (*database, error) {
	doc, err := parseXMLTree(data)
	if err != nil {
		return nil, err
	}
	meta := doc.child("Meta")
	if meta == nil {
		return nil, errFormat("error parsing XML inside KDBX: missing field `Meta`")
	}
	rootEl := doc.child("Root")
	if rootEl == nil {
		return nil, errFormat("error parsing XML inside KDBX: missing field `Root`")
	}
	rootGroup := rootEl.child("Group")
	if rootGroup == nil {
		return nil, errFormat("error parsing XML inside KDBX: missing field `Group`")
	}

	db := &database{}
	if el := meta.child("RecycleBinEnabled"); el != nil {
		v, err := parseOptBool(el.text.String())
		if err != nil {
			return nil, err
		}
		db.recycleBinEnabled = v
	}
	if el := meta.child("RecycleBinUUID"); el != nil && strings.TrimSpace(el.text.String()) != "" {
		u, err := parseUUID(el.text.String())
		if err != nil {
			return nil, err
		}
		db.recycleBinUUID = &u
	}

	l := &xmlLoader{inner: inner, groups: map[[16]byte]bool{}, entries: map[[16]byte]bool{}}

	// Meta/Binaries are unprotected first: they consume the inner stream before the entries.
	if bins := meta.child("Binaries"); bins != nil {
		for _, b := range bins.children {
			if b.name != "Binary" {
				continue
			}
			if err := l.binary(b); err != nil {
				return nil, err
			}
		}
	}

	root, err := l.group(rootGroup, true)
	if err != nil {
		return nil, err
	}
	db.root = root
	return db, nil
}

// binary is meta::Binary::xml_to_db (only its effect on the inner stream matters here).
func (l *xmlLoader) binary(b *xnode) error {
	id, ok := b.attr("ID")
	if !ok {
		return errFormat("error parsing XML inside KDBX: missing field `@ID`")
	}
	if _, err := strconv.ParseUint(id, 10, 64); err != nil {
		return errFormat("error parsing XML inside KDBX: invalid binary ID")
	}
	var compressed, protected *bool
	var err error
	if v, ok := b.attr("Compressed"); ok {
		if compressed, err = parseOptBool(v); err != nil {
			return err
		}
	}
	if v, ok := b.attr("Protected"); ok {
		if protected, err = parseOptBool(v); err != nil {
			return err
		}
	}
	data, ok := decodeBase64Strict(b.text.String())
	if !ok {
		return errFormat("error unprotecting entry: invalid base64")
	}
	if protected != nil && *protected {
		data = l.inner.decrypt(data)
	}
	if compressed != nil && *compressed {
		if _, err := gunzip(data); err != nil {
			return err
		}
	}
	return nil
}

func (l *xmlLoader) group(n *xnode, isRoot bool) (*group, error) {
	uuidEl := n.child("UUID")
	if uuidEl == nil {
		return nil, errFormat("error parsing XML inside KDBX: missing field `UUID`")
	}
	uuid, err := parseUUID(uuidEl.text.String())
	if err != nil {
		return nil, err
	}
	nameEl := n.child("Name")
	if nameEl == nil {
		return nil, errFormat("error parsing XML inside KDBX: missing field `Name`")
	}
	if l.groups[uuid] {
		return nil, errFormat(fmt.Sprintf("duplicate group ID %x", uuid))
	}
	l.groups[uuid] = true
	g := &group{uuid: uuid, name: nameEl.text.String()}
	for _, c := range n.children {
		switch c.name {
		case "Group":
			sub, err := l.group(c, false)
			if err != nil {
				return nil, err
			}
			g.groups = append(g.groups, sub)
		case "Entry":
			e, err := l.entry(c, false)
			if err != nil {
				return nil, err
			}
			g.entries = append(g.entries, e)
		}
	}
	return g, nil
}

func (l *xmlLoader) entry(n *xnode, historical bool) (*entry, error) {
	uuidEl := n.child("UUID")
	if uuidEl == nil {
		return nil, errFormat("error parsing XML inside KDBX: missing field `UUID`")
	}
	uuid, err := parseUUID(uuidEl.text.String())
	if err != nil {
		return nil, err
	}
	if !historical {
		if l.entries[uuid] {
			return nil, errFormat(fmt.Sprintf("duplicate entry ID %x", uuid))
		}
		l.entries[uuid] = true
	}
	e := newEntry()
	for _, c := range n.children {
		if c.name != "String" {
			continue
		}
		keyEl := c.child("Key")
		if keyEl == nil {
			return nil, errFormat("error parsing XML inside KDBX: missing field `Key`")
		}
		valueEl := c.child("Value")
		if valueEl == nil {
			return nil, errFormat("error parsing XML inside KDBX: missing field `Value`")
		}
		protected := false
		if v, ok := valueEl.attr("Protected"); ok {
			if protected, err = parseBool(v); err != nil {
				return nil, err
			}
		}
		text := valueEl.text.String()
		if strings.TrimSpace(text) == "" {
			// cs_opt_string: a missing or blank value is None and the field is not stored.
			continue
		}
		value := text
		if protected {
			raw, ok := decodeBase64Strict(text)
			if !ok {
				return nil, errFormat("error unprotecting entry: invalid base64")
			}
			value = string(bytes.ToValidUTF8(l.inner.decrypt(raw), []byte("�")))
		}
		e.set(keyEl.text.String(), value, protected)
	}
	if h := n.child("History"); h != nil {
		for _, he := range h.children {
			if he.name != "Entry" {
				continue
			}
			// History entries are decrypted (they consume the inner stream) but not imported.
			if _, err := l.entry(he, true); err != nil {
				return nil, err
			}
		}
	}
	return e, nil
}
