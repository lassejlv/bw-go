package exporter

import (
	"archive/zip"
	"bytes"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/lassejlv/bw-go/internal/crypto"
	"github.com/lassejlv/bw-go/internal/vault"
)

// zipBuilder mimics JSZip's in-memory file map: entries keep their insertion order, re-adding a
// path replaces its content in place, and adding a file creates its parent folders first.
type zipBuilder struct {
	names []string
	files map[string][]byte // nil content = folder
	dirs  map[string]bool
}

func newZipBuilder() *zipBuilder {
	return &zipBuilder{files: map[string][]byte{}, dirs: map[string]bool{}}
}

// parentFolder mirrors JSZip's parentFolder helper.
func parentFolder(path string) string {
	path = strings.TrimSuffix(path, "/")
	if i := strings.LastIndex(path, "/"); i > 0 {
		return path[:i]
	}
	return ""
}

func (z *zipBuilder) add(name string, data []byte, dir bool) {
	if parent := parentFolder(name); parent != "" {
		z.folder(parent)
	}
	if _, ok := z.files[name]; !ok {
		z.names = append(z.names, name)
	}
	z.files[name] = data
	z.dirs[name] = dir
}

// folder mirrors JSZip folderAdd (with a forced trailing slash) and returns the folder path.
func (z *zipBuilder) folder(name string) string {
	if !strings.HasSuffix(name, "/") {
		name += "/"
	}
	if _, ok := z.files[name]; !ok {
		z.add(name, nil, true)
	}
	return name
}

func (z *zipBuilder) file(name string, data []byte) {
	if data == nil {
		data = []byte{}
	}
	z.add(name, data, false)
}

// generate writes the archive (JSZip default: STORE, DOS platform).
func (z *zipBuilder) generate(now time.Time) ([]byte, error) {
	var buf bytes.Buffer
	w := zip.NewWriter(&buf)
	for _, name := range z.names {
		fh := &zip.FileHeader{Name: name, Method: zip.Store, Modified: now}
		if z.dirs[name] {
			fh.ExternalAttrs = 0x10 // MS-DOS directory attribute
		}
		fw, err := w.CreateHeader(fh)
		if err != nil {
			return nil, err
		}
		if !z.dirs[name] {
			if _, err := fw.Write(z.files[name]); err != nil {
				return nil, err
			}
		}
	}
	if err := w.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

var (
	zipFolderDisallowed = regexp.MustCompile(`[/\\><:"|?*]`)
	zipFileDisallowed   = regexp.MustCompile(`[/\\><:"|?*.]`)
	zipMultiUnderscore  = regexp.MustCompile(`__+`)
)

// individualZipExport mirrors IndividualVaultExportService.getDecryptedExportZip.
func (s *Service) individualZipExport() (*ExportedVault, error) {
	z := newZipBuilder()
	exp, err := s.individualDecryptedExport(FormatJSON)
	if err != nil {
		return nil, err
	}
	z.file("data.json", exp.Data)
	attachmentsFolder := z.folder("attachments")

	skipped := 0
	cipherNames := map[string]int{}
	for _, c := range s.Vault.Ciphers() {
		if len(c.Attachments) == 0 || c.DeletedDate != nil || c.OrganizationID != nil {
			continue
		}
		folderName := zipMultiUnderscore.ReplaceAllString(zipFolderDisallowed.ReplaceAllString(c.Name, "_"), "_")
		if n, ok := cipherNames[c.Name]; !ok {
			cipherNames[c.Name] = 1
		} else {
			cipherNames[c.Name] = n + 1
			folderName += fmt.Sprintf("_%d", n)
		}
		cipherFolder := z.folder(attachmentsFolder + folderName)

		fileNames := map[string]int{}
		for i := range c.Attachments {
			a := &c.Attachments[i]
			full, data, err := s.exportAttachment(c, a, fileNames)
			if err != nil {
				s.logError("Failed to export attachment: Cipher Id: "+c.ID, err)
				skipped++
				continue
			}
			z.file(cipherFolder+full, data)
		}
	}

	now := s.now()
	data, err := z.generate(now)
	if err != nil {
		return nil, err
	}
	return &ExportedVault{Type: TypeZip, Data: data, FileName: GetFileName("", FormatZip, now), SkippedAttachmentCount: skipped}, nil
}

// exportAttachment downloads and decrypts one attachment and returns its sanitized, de-duplicated
// file name.
func (s *Service) exportAttachment(c *vault.CipherView, a *vault.AttachmentView, fileNames map[string]int) (string, []byte, error) {
	if s.API == nil {
		return "", nil, errors.New("no API client")
	}
	id := ""
	if a.ID != nil {
		id = *a.ID
	}
	url, err := s.API.GetAttachmentData(c.ID, id)
	if err != nil {
		return "", nil, err
	}
	enc, err := s.API.DownloadAttachment(url)
	if err != nil {
		return "", nil, err
	}
	dec, err := s.decryptAttachment(c, a, enc)
	if err != nil {
		return "", nil, err
	}
	if a.FileName == nil {
		return "", nil, errors.New("Cannot read properties of undefined (reading 'split')")
	}
	parts := strings.Split(*a.FileName, ".")
	base, suffix := *a.FileName, ""
	if len(parts) > 1 {
		base = strings.Join(parts[:len(parts)-1], "")
		suffix = "." + parts[len(parts)-1]
	}
	base = zipMultiUnderscore.ReplaceAllString(zipFileDisallowed.ReplaceAllString(base, "_"), "_")
	full := base + suffix
	if n, ok := fileNames[full]; !ok {
		fileNames[full] = 1
	} else {
		fileNames[full] = n + 1
		full = fmt.Sprintf("%s_%d%s", base, n, suffix)
	}
	return full, dec, nil
}

// decryptAttachment mirrors cipherEncryptionService.decryptAttachmentContent: the attachment key
// (wrapped by the cipher key) when present, otherwise the cipher key itself.
func (s *Service) decryptAttachment(c *vault.CipherView, a *vault.AttachmentView, enc []byte) ([]byte, error) {
	key := a.Key
	if key == nil {
		domain, err := s.Vault.EncryptedCipher(c.ID)
		if err != nil {
			return nil, err
		}
		if key, err = s.Vault.Keys().CipherKey(domain); err != nil {
			return nil, err
		}
	}
	return crypto.DecryptBytes(enc, key)
}
