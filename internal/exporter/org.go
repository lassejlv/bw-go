package exporter

import (
	"encoding/json"
	"errors"
	"sort"

	"github.com/lassejlv/bw-go/internal/crypto"
	"github.com/lassejlv/bw-go/internal/state"
	"github.com/lassejlv/bw-go/internal/vault"
)

// ---------- OrganizationVaultExportService ----------

func (s *Service) organizationExport(organizationID, format string, onlyManagedCollections bool) (*ExportedVault, error) {
	if format == "" {
		format = FormatCSV
	}
	if isNullOrWhitespace(organizationID) {
		return nil, errors.New("OrganizationId must be set")
	}
	if format == FormatZip {
		return nil, errors.New("Zip export not supported for organization")
	}
	if format == FormatEncryptedJSON {
		var data []byte
		var err error
		if onlyManagedCollections {
			data, err = s.encryptedManagedExport(organizationID)
		} else {
			data, err = s.organizationEncryptedExport(organizationID)
		}
		if err != nil {
			return nil, err
		}
		return &ExportedVault{Type: TypeText, Data: data, FileName: GetFileName("org", FormatEncryptedJSON, s.now())}, nil
	}
	var data []byte
	var err error
	if onlyManagedCollections {
		data, err = s.decryptedManagedExport(organizationID, format)
	} else {
		data, err = s.organizationDecryptedExport(organizationID, format)
	}
	if err != nil {
		return nil, err
	}
	return &ExportedVault{Type: TypeText, Data: data, FileName: GetFileName("org", format, s.now())}, nil
}

func (s *Service) fetchOrganizationExport(organizationID string) (*OrganizationExportResponse, error) {
	if s.API == nil {
		return nil, errors.New("no API client")
	}
	return s.API.GetOrganizationExport(organizationID)
}

// parseExportCiphers parses the response ciphers that are not deleted (`deletedDate === null`).
func parseExportCiphers(raws []json.RawMessage) ([]*vault.Cipher, error) {
	var out []*vault.Cipher
	for _, raw := range raws {
		c, err := vault.ParseCipher(raw)
		if err != nil {
			return nil, err
		}
		if c.DeletedDate == nil {
			out = append(out, c)
		}
	}
	return out, nil
}

func parseExportCollections(raws []json.RawMessage) ([]*vault.Collection, error) {
	var out []*vault.Collection
	for _, raw := range raws {
		c := &vault.Collection{}
		if err := json.Unmarshal(raw, c); err != nil {
			return nil, err
		}
		if c.Name == nil || c.OrganizationID == "" {
			return nil, errors.New("CollectionData must contain name and organizationId.")
		}
		out = append(out, c)
	}
	return out, nil
}

func (s *Service) organizationDecryptedExport(organizationID, format string) ([]byte, error) {
	exportData, err := s.fetchOrganizationExport(organizationID)
	if err != nil {
		return nil, err
	}
	keys := s.Vault.Keys()
	restrictions := s.Vault.RestrictedTypes()
	decCollections := []*vault.CollectionView{}
	decCiphers := []*vault.CipherView{}
	if exportData != nil {
		cols, err := parseExportCollections(exportData.Collections)
		if err != nil {
			return nil, err
		}
		for _, c := range cols {
			decCollections = append(decCollections, vault.DecryptCollection(c, keys))
		}
		ciphers, err := parseExportCiphers(exportData.Ciphers)
		if err != nil {
			return nil, err
		}
		for _, c := range ciphers {
			view, err := vault.DecryptCipher(c, keys)
			if err != nil {
				// cipherService.decrypt logs and completes empty; firstValueFrom then rejects.
				s.logError("Failed to decrypt cipher", err)
				return nil, errEmptySequence
			}
			if !view.Partial && !vault.IsCipherRestricted(view.Type, view.OrganizationID, restrictions) {
				decCiphers = append(decCiphers, view)
			}
		}
	}
	if format == FormatCSV {
		return []byte(buildOrganizationCSV(decCollections, decCiphers)), nil
	}
	return buildOrganizationJSON(decCollections, decCiphers)
}

func (s *Service) organizationEncryptedExport(organizationID string) ([]byte, error) {
	restrictions := s.Vault.RestrictedTypes()
	exportData, err := s.fetchOrganizationExport(organizationID)
	if err != nil {
		return nil, err
	}
	if exportData == nil {
		return nil, nil
	}
	collections, err := parseExportCollections(exportData.Collections)
	if err != nil {
		return nil, err
	}
	all, err := parseExportCiphers(exportData.Ciphers)
	if err != nil {
		return nil, err
	}
	var ciphers []*vault.Cipher
	for _, c := range all {
		if !c.IsPartial() && !vault.IsCipherRestricted(c.Type, c.OrganizationID, restrictions) {
			ciphers = append(ciphers, c)
		}
	}
	return s.buildEncryptedOrgExport(organizationID, collections, ciphers)
}

// managedCollectionIDs reports whether any of ids is in the managed set.
func inCollections(ids []string, set map[string]bool) bool {
	for _, id := range ids {
		if set[id] {
			return true
		}
	}
	return false
}

func (s *Service) decryptedManagedExport(organizationID, format string) ([]byte, error) {
	all := s.Vault.Ciphers()
	decCollections := []*vault.CollectionView{}
	managed := map[string]bool{}
	for _, c := range s.Vault.Collections() {
		if c.OrganizationID == organizationID && c.Manage {
			decCollections = append(decCollections, c)
			managed[c.ID] = true
		}
	}
	restrictions := s.Vault.RestrictedTypes()
	decCiphers := []*vault.CipherView{}
	for _, c := range all {
		if c.DeletedDate == nil && c.OrganizationID != nil && *c.OrganizationID == organizationID &&
			inCollections(c.CollectionIDs, managed) &&
			!vault.IsCipherRestricted(c.Type, c.OrganizationID, restrictions) {
			decCiphers = append(decCiphers, c)
		}
	}
	if format == FormatCSV {
		return []byte(buildOrganizationCSV(decCollections, decCiphers)), nil
	}
	return buildOrganizationJSON(decCollections, decCiphers)
}

func (s *Service) encryptedManagedExport(organizationID string) ([]byte, error) {
	all := encryptedCiphers(s.Vault)
	encCollections := []*vault.Collection{}
	managed := map[string]bool{}
	vd := s.Vault.Account().Vault
	for _, id := range state.OrderedIDs(vd.Collections, vd.CollectionOrder) {
		raw := vd.Collections[id]
		c := &vault.Collection{}
		if json.Unmarshal(raw, c) != nil {
			continue
		}
		if c.OrganizationID == organizationID && c.Manage {
			encCollections = append(encCollections, c)
			managed[c.ID] = true
		}
	}
	sort.SliceStable(encCollections, func(i, j int) bool { return encCollections[i].ID < encCollections[j].ID })
	restrictions := s.Vault.RestrictedTypes()
	var ciphers []*vault.Cipher
	for _, c := range all {
		if !c.IsPartial() && c.DeletedDate == nil && c.OrganizationID != nil && *c.OrganizationID == organizationID &&
			inCollections(c.CollectionIDs, managed) &&
			!vault.IsCipherRestricted(c.Type, c.OrganizationID, restrictions) {
			ciphers = append(ciphers, c)
		}
	}
	return s.buildEncryptedOrgExport(organizationID, encCollections, ciphers)
}

func (s *Service) buildEncryptedOrgExport(organizationID string, collections []*vault.Collection, ciphers []*vault.Cipher) ([]byte, error) {
	key, err := s.Vault.Keys().OrgKey(organizationID)
	if err != nil || key == nil {
		return nil, errors.New("No encryption key found for organization")
	}
	encKeyValidation, err := crypto.EncryptString(newGUID(), key)
	if err != nil {
		return nil, err
	}
	doc := encryptedOrgJSON{Encrypted: true, EncKeyValidation: encKeyValidation,
		Collections: []vault.CollectionWithIDExport{}, Items: []*vault.CipherWithIDExport{}}
	for _, c := range collections {
		name := ""
		if c.Name != nil {
			name = *c.Name
		}
		doc.Collections = append(doc.Collections, vault.CollectionWithIDExport{
			ID: c.ID, OrganizationID: c.OrganizationID, Name: name, ExternalID: vault.NullFromPtr(c.ExternalID),
		})
	}
	for _, c := range ciphers {
		doc.Items = append(doc.Items, vault.BuildCipherExportFromDomain(c))
	}
	return stringify(doc)
}

func buildOrganizationCSV(collections []*vault.CollectionView, ciphers []*vault.CipherView) string {
	byID := map[string]*vault.CollectionView{}
	for _, c := range collections {
		byID[c.ID] = c
	}
	rows := []csvRow{}
	for _, c := range ciphers {
		if c.Type != vault.CipherTypeLogin && c.Type != vault.CipherTypeSecureNote {
			continue
		}
		names := csvArray{}
		for _, id := range c.CollectionIDs {
			if col, ok := byID[id]; ok {
				n := col.DisplayName()
				names = append(names, &n)
			}
		}
		rows = append(rows, append(csvRow{names}, buildCommonCipher(c)...))
	}
	return Unparse(OrganizationCSVFields, rows)
}

func buildOrganizationJSON(collections []*vault.CollectionView, ciphers []*vault.CipherView) ([]byte, error) {
	doc := unencryptedOrgJSON{Encrypted: false, Collections: []vault.CollectionWithIDExport{}, Items: []*vault.CipherWithIDExport{}}
	for _, c := range collections {
		doc.Collections = append(doc.Collections, vault.BuildCollectionExport(c))
	}
	for _, c := range ciphers {
		e := vault.BuildCipherExport(c)
		e.Key = vault.Opt[string]{} // delete cipher.key
		doc.Items = append(doc.Items, e)
	}
	return stringify(doc)
}
