package exporter

import (
	"encoding/json"
	"errors"

	"github.com/lassejlv/bw-go/internal/crypto"
	"github.com/lassejlv/bw-go/internal/state"
	"github.com/lassejlv/bw-go/internal/vault"
)

// ---------- IndividualVaultExportService ----------

func (s *Service) individualExport(format string) (*ExportedVault, error) {
	switch format {
	case FormatEncryptedJSON:
		return s.individualEncryptedExport()
	case FormatZip:
		return s.individualZipExport()
	}
	return s.individualDecryptedExport(format)
}

func (s *Service) individualPasswordProtectedExport(password string) (*ExportedVault, error) {
	exp, err := s.individualExport(FormatJSON)
	if err != nil {
		return nil, err
	}
	if exp.Type != TypeText {
		return nil, errors.New("Unexpected export type")
	}
	data, err := s.buildPasswordExport(exp.Data, password)
	if err != nil {
		return nil, err
	}
	return &ExportedVault{Type: TypeText, Data: data, FileName: GetFileName("", FormatEncryptedJSON, s.now())}, nil
}

// decryptedIndividualData mirrors the data gathering of getDecryptedExport: decrypted folders and
// the decrypted ciphers that are not deleted and not of a restricted type.
func (s *Service) decryptedIndividualData() ([]*vault.FolderView, []*vault.CipherView) {
	restrictions := s.Vault.RestrictedTypes()
	var ciphers []*vault.CipherView
	for _, c := range s.Vault.Ciphers() {
		if c.DeletedDate == nil && !vault.IsCipherRestricted(c.Type, c.OrganizationID, restrictions) {
			ciphers = append(ciphers, c)
		}
	}
	return s.Vault.Folders(), ciphers
}

func (s *Service) individualDecryptedExport(format string) (*ExportedVault, error) {
	folders, ciphers := s.decryptedIndividualData()
	if format == FormatCSV {
		return &ExportedVault{Type: TypeText, Data: []byte(buildIndividualCSV(folders, ciphers)),
			FileName: GetFileName("", FormatCSV, s.now())}, nil
	}
	data, err := buildIndividualJSON(folders, ciphers)
	if err != nil {
		return nil, err
	}
	return &ExportedVault{Type: TypeText, Data: data, FileName: GetFileName("", FormatJSON, s.now())}, nil
}

func buildIndividualCSV(folders []*vault.FolderView, ciphers []*vault.CipherView) string {
	byID := map[string]*vault.FolderView{}
	for _, f := range folders {
		if f.ID != "" {
			byID[f.ID] = f
		}
	}
	rows := []csvRow{}
	for _, c := range ciphers {
		if c.Type != vault.CipherTypeLogin && c.Type != vault.CipherTypeSecureNote {
			continue
		}
		if c.OrganizationID != nil {
			continue
		}
		var folder, favorite any
		if c.FolderID != nil {
			if f, ok := byID[*c.FolderID]; ok {
				folder = f.Name
			}
		}
		if c.Favorite {
			favorite = 1
		}
		rows = append(rows, append(csvRow{folder, favorite}, buildCommonCipher(c)...))
	}
	return Unparse(IndividualCSVFields, rows)
}

func buildIndividualJSON(folders []*vault.FolderView, ciphers []*vault.CipherView) ([]byte, error) {
	doc := unencryptedIndividualJSON{Encrypted: false, Folders: []vault.FolderWithIDExport{}, Items: []*vault.CipherWithIDExport{}}
	for _, f := range folders {
		if f.ID == "" {
			continue
		}
		doc.Folders = append(doc.Folders, vault.BuildFolderExport(f))
	}
	for _, c := range ciphers {
		if c.OrganizationID != nil {
			continue
		}
		e := vault.BuildCipherExport(c)
		e.CollectionIDs = vault.Null[[]string]()
		e.Key = vault.Opt[string]{} // delete cipher.key
		doc.Items = append(doc.Items, e)
	}
	return stringify(doc)
}

// encryptedFolders returns the stored (encrypted) folders in server order.
func encryptedFolders(v *vault.Vault) []*vault.Folder {
	out := []*vault.Folder{}
	vd := v.Account().Vault
	for _, id := range state.OrderedIDs(vd.Folders, vd.FolderOrder) {
		f := &vault.Folder{}
		if json.Unmarshal(vd.Folders[id], f) == nil {
			out = append(out, f)
		}
	}
	return out
}

// encryptedCiphers returns the stored (encrypted) ciphers sorted by id. The state keeps them in
// a map, so the server order upstream preserves is not available; sorting keeps exports stable.
func encryptedCiphers(v *vault.Vault) []*vault.Cipher {
	return v.EncryptedCiphers() // server order
}

func (s *Service) individualEncryptedExport() (*ExportedVault, error) {
	restrictions := s.Vault.RestrictedTypes()
	folders := encryptedFolders(s.Vault)
	var ciphers []*vault.Cipher
	for _, c := range encryptedCiphers(s.Vault) {
		if !c.IsPartial() && c.DeletedDate == nil && !vault.IsCipherRestricted(c.Type, c.OrganizationID, restrictions) {
			ciphers = append(ciphers, c)
		}
	}
	userKey := s.Vault.Keys().UserKey()
	if userKey == nil {
		return nil, errors.New("No user key found")
	}
	encKeyValidation, err := crypto.EncryptString(newGUID(), userKey)
	if err != nil {
		return nil, err
	}
	doc := encryptedIndividualJSON{Encrypted: true, EncKeyValidation: encKeyValidation,
		Folders: []vault.FolderWithIDExport{}, Items: []*vault.CipherWithIDExport{}}
	for _, f := range folders {
		if f.ID == "" {
			continue
		}
		name := ""
		if f.Name != nil {
			name = *f.Name
		}
		doc.Folders = append(doc.Folders, vault.FolderWithIDExport{Name: name, ID: f.ID})
	}
	for _, c := range ciphers {
		if c.OrganizationID != nil {
			continue
		}
		e := vault.BuildCipherExportFromDomain(c)
		e.CollectionIDs = vault.Null[[]string]()
		doc.Items = append(doc.Items, e)
	}
	data, err := stringify(doc)
	if err != nil {
		return nil, err
	}
	return &ExportedVault{Type: TypeText, Data: data, FileName: GetFileName("", FormatEncryptedJSON, s.now())}, nil
}
