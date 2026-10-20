// Package psono ports libs/importer/src/importers/psono/psono-json-importer.ts (psonojson).
package psono

import (
	"github.com/lassejlv/bw-go/internal/importer"
	"github.com/lassejlv/bw-go/internal/importer/jsvalue"
	"github.com/lassejlv/bw-go/internal/importer/model"
)

func init() { importer.Register("psonojson", New) }

func set(keys ...string) map[string]bool {
	m := make(map[string]bool, len(keys))
	for _, k := range keys {
		m[k] = true
	}
	return m
}

var (
	websiteMappedValues = set(
		"type",
		"name",
		"website_password_title",
		"website_password_notes",
		"website_password_username",
		"website_password_password",
		"website_password_url",
		"autosubmit",
		"website_password_auto_submit",
		"urlfilter",
		"website_password_url_filter",
	)
	appPwdMappedValues = set(
		"type",
		"name",
		"application_password_title",
		"application_password_notes",
		"application_password_username",
		"application_password_password",
	)
	bookmarkMappedValues = set("type", "name", "bookmark_title", "bookmark_notes", "bookmark_url")
	notesMappedValues    = set("type", "name", "note_title", "note_notes")
	totpMappedValues     = set("type", "name", "totp_title", "totp_notes", "totp_code")
	envVariablesMapped   = set(
		"type",
		"name",
		"environment_variables_title",
		"environment_variables_notes",
		"environment_variables_variables",
	)
	gpgMappedValues = set(
		"type",
		"name",
		"mail_gpg_own_key_title",
		"mail_gpg_own_key_public",
		"mail_gpg_own_key_name",
		"mail_gpg_own_key_email",
		"mail_gpg_own_key_private",
	)
)

// Importer is PsonoJsonImporter.
type Importer struct{ importer.Base }

// New constructs the importer.
func New(opts importer.Options) importer.Importer { return &Importer{Base: importer.NewBase(opts)} }

// Parse implements importer.Importer.
func (i *Importer) Parse(data string) (_ *model.ImportResult, err error) {
	defer jsvalue.CatchTypeError(&err)
	result := model.NewImportResult()
	psonoExport, err := jsvalue.Parse(data)
	if err != nil {
		return nil, err
	}
	if psonoExport.Nullish() {
		result.Success = false
		return result, nil
	}

	i.parseFolders(result, psonoExport.Get("folders"), nil)
	i.handleItemParsing(result, psonoExport.Get("items"), nil)

	if i.Organization() {
		i.MoveFoldersToCollections(result)
	}

	result.Success = true
	return result, nil
}

func (i *Importer) parseFolders(result *model.ImportResult, folders *jsvalue.Value, parentName *jsvalue.Value) {
	if folders.Nullish() || folders.LengthIs(0) {
		return
	}

	folders.ForEach("folders", func(folder *jsvalue.Value) {
		items, subfolders := folder.Get("items"), folder.Get("folders")
		folderHasItems := !items.Nullish() && items.LengthGreaterThan(0)
		folderHasSubfolders := !subfolders.Nullish() && subfolders.LengthGreaterThan(0)

		if !folderHasItems && !folderHasSubfolders {
			return
		}

		// folder.name = parentName + "/" + folder.name (the folder object is mutated upstream).
		name := folder.Get("name")
		if !parentName.IsNullOrWhitespace() {
			name = jsvalue.NewString(parentName.Str() + "/" + name.JSString())
			folder.Set("name", name)
		}

		if folderHasSubfolders {
			i.parseFolders(result, subfolders, name)
		}

		if !folderHasItems {
			i.ProcessFolder(result, name.Str(), folderHasItems)
		} else {
			i.handleItemParsing(result, items, name)
		}
	})
}

func (i *Importer) handleItemParsing(result *model.ImportResult, items *jsvalue.Value, folderName *jsvalue.Value) {
	if items.Nullish() || items.LengthIs(0) {
		return
	}

	items.ForEach("items", func(record *jsvalue.Value) {
		cipher := i.parsePsonoItem(record)
		i.ProcessFolder(result, folderName.Str(), true)
		i.CleanupCipher(cipher)
		result.Ciphers = append(result.Ciphers, cipher)
	})
}

func (i *Importer) parsePsonoItem(item *jsvalue.Value) *model.CipherView {
	cipher := i.InitLoginCipher()

	switch item.Get("type").Str() {
	case "website_password":
		i.parseWebsiteLogins(item, cipher)
	case "application_password":
		i.parseApplicationPasswords(item, cipher)
	case "environment_variables":
		i.parseEnvironmentVariables(item, cipher)
	case "totp":
		i.parseTOTP(item, cipher)
	case "bookmark":
		i.parseBookmarks(item, cipher)
	// Skipping this until we can save GPG into notes/custom fields
	// case "mail_gpg_own_key":
	//   i.parseGPG(item, cipher)
	case "note":
		i.parseNotes(item, cipher)
	}

	return cipher
}

func (i *Importer) parseWebsiteLogins(entry *jsvalue.Value, cipher *model.CipherView) {
	if entry.Nullish() || entry.Get("type").Str() != "website_password" {
		return
	}

	cipher.Name = entry.Get("website_password_title").Str()
	cipher.Notes = entry.Get("website_password_notes").Str()

	cipher.Login.Username = entry.Get("website_password_username").Str()
	cipher.Login.Password = entry.Get("website_password_password").Str()

	cipher.Login.Uris = jsvalue.MakeUriArray(&i.Base, entry.Get("website_password_url"))

	autoSubmit := "" // entry.website_password_auto_submit?.ToString()
	if v := entry.Get("website_password_auto_submit"); !v.Nullish() {
		autoSubmit = v.ToString()
	}
	i.ProcessKvp(cipher, "website_password_auto_submit", autoSubmit, model.FieldTypeBoolean)

	i.ProcessKvp(cipher, "website_password_url_filter", entry.Get("website_password_url_filter").Str())

	i.importUnmappedFields(cipher, entry, websiteMappedValues)
}

func (i *Importer) parseApplicationPasswords(entry *jsvalue.Value, cipher *model.CipherView) {
	if entry.Nullish() || entry.Get("type").Str() != "application_password" {
		return
	}

	cipher.Name = entry.Get("application_password_title").Str()
	cipher.Notes = entry.Get("application_password_notes").Str()

	cipher.Login.Username = entry.Get("application_password_username").Str()
	cipher.Login.Password = entry.Get("application_password_password").Str()

	i.importUnmappedFields(cipher, entry, appPwdMappedValues)
}

func (i *Importer) parseBookmarks(entry *jsvalue.Value, cipher *model.CipherView) {
	if entry.Nullish() || entry.Get("type").Str() != "bookmark" {
		return
	}

	cipher.Name = entry.Get("bookmark_title").Str()
	cipher.Notes = entry.Get("bookmark_notes").Str()

	cipher.Login.Uris = jsvalue.MakeUriArray(&i.Base, entry.Get("bookmark_url"))

	i.importUnmappedFields(cipher, entry, bookmarkMappedValues)
}

func (i *Importer) parseNotes(entry *jsvalue.Value, cipher *model.CipherView) {
	if entry.Nullish() || entry.Get("type").Str() != "note" {
		return
	}
	cipher.Type = model.CipherTypeSecureNote
	cipher.SecureNote = &model.SecureNoteView{Type: model.SecureNoteTypeGeneric}
	cipher.Name = entry.Get("note_title").Str()
	cipher.Notes = entry.Get("note_notes").Str()

	i.importUnmappedFields(cipher, entry, notesMappedValues)
}

func (i *Importer) parseTOTP(entry *jsvalue.Value, cipher *model.CipherView) {
	if entry.Nullish() || entry.Get("type").Str() != "totp" {
		return
	}

	cipher.Name = entry.Get("totp_title").Str()
	cipher.Notes = entry.Get("totp_notes").Str()

	cipher.Login.Totp = entry.Get("totp_code").Str()

	i.importUnmappedFields(cipher, entry, totpMappedValues)
}

func (i *Importer) parseEnvironmentVariables(entry *jsvalue.Value, cipher *model.CipherView) {
	if entry.Nullish() || entry.Get("type").Str() != "environment_variables" {
		return
	}

	cipher.Type = model.CipherTypeSecureNote
	cipher.SecureNote = &model.SecureNoteView{Type: model.SecureNoteTypeGeneric}
	cipher.Name = entry.Get("environment_variables_title").Str()
	cipher.Notes = entry.Get("environment_variables_notes").Str()

	entry.Get("environment_variables_variables").ForEach("entry.environment_variables_variables", func(kvPair *jsvalue.Value) {
		i.ProcessKvp(cipher, kvPair.Get("key").Str(), kvPair.Get("value").Str())
	})

	i.importUnmappedFields(cipher, entry, envVariablesMapped)
}

// parseGPG is kept for parity; upstream does not call it yet ("Skipping this until we can save GPG
// into notes/custom fields").
func (i *Importer) parseGPG(entry *jsvalue.Value, cipher *model.CipherView) {
	if entry.Nullish() || entry.Get("type").Str() != "mail_gpg_own_key" {
		return
	}

	cipher.Type = model.CipherTypeSecureNote
	cipher.SecureNote = &model.SecureNoteView{Type: model.SecureNoteTypeGeneric}
	cipher.Name = entry.Get("mail_gpg_own_key_title").Str()
	cipher.Notes = entry.Get("mail_gpg_own_key_public").Str()

	i.ProcessKvp(cipher, "mail_gpg_own_key_name", entry.Get("mail_gpg_own_key_name").Str())
	i.ProcessKvp(cipher, "mail_gpg_own_key_email", entry.Get("mail_gpg_own_key_email").Str())
	i.ProcessKvp(cipher, "mail_gpg_own_key_private", entry.Get("mail_gpg_own_key_private").Str(), model.FieldTypeHidden)

	i.importUnmappedFields(cipher, entry, gpgMappedValues)
}

func (i *Importer) importUnmappedFields(cipher *model.CipherView, entry *jsvalue.Value, mappedValues map[string]bool) {
	for _, key := range entry.OwnKeys() {
		if mappedValues[key] {
			continue
		}
		i.ProcessKvp(cipher, key, entry.Get(key).ToString())
	}
}

var _ = (*Importer).parseGPG
