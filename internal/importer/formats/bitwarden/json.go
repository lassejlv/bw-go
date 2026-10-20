package bitwarden

import (
	"errors"

	"github.com/lassejlv/bw-go/internal/importer"
	"github.com/lassejlv/bw-go/internal/importer/model"
)

// JsonImporter is BitwardenJsonImporter: unencrypted Bitwarden JSON exports. Upstream never
// registers it directly; "bitwardenjson" goes through PasswordProtectedImporter, which falls back
// to EncryptedJsonImporter and then to this one.
type JsonImporter struct {
	importer.Base
}

// NewJson constructs the unencrypted importer.
func NewJson(opts importer.Options) *JsonImporter {
	return &JsonImporter{Base: importer.NewBase(opts)}
}

// Parse implements importer.Importer.
func (i *JsonImporter) Parse(data string) (*model.ImportResult, error) {
	results, err := parseExportFile(data)
	if err != nil {
		return nil, err
	}
	if results == nil || results.Items == nil {
		r := model.NewImportResult()
		r.Success = false
		return r, nil
	}
	if !results.isUnencrypted() {
		return nil, errors.New("Data is encrypted. Use BitwardenEncryptedJsonImporter instead.")
	}
	return i.parseDecrypted(results)
}

func (i *JsonImporter) parseDecrypted(results *exportFile) (*model.ImportResult, error) {
	result := model.NewImportResult()

	groupings := map[string]int{}
	if results.Collections != nil { // isOrgUnEncrypted
		for _, c := range results.Collections {
			groupings[string(c.ID)] = len(result.Collections)
			result.Collections = append(result.Collections, &model.CollectionView{
				ID: string(c.ID), Name: string(c.Name), ExternalID: string(c.ExternalID),
			})
		}
	} else if results.Folders != nil {
		for _, f := range results.Folders {
			groupings[string(f.ID)] = len(result.Folders)
			result.Folders = append(result.Folders, &model.FolderView{ID: string(f.ID), Name: string(f.Name)})
		}
	}

	for _, raw := range results.Items {
		c, err := parseCipherExport(raw)
		if err != nil {
			return nil, err
		}
		cipher, err := c.toView(plain)
		if err != nil {
			return nil, err
		}
		i.addCipher(result, c, cipher, groupings)
	}

	result.Success = true
	return result, nil
}

// addCipher applies the shared tail of parseDecrypted/parseEncrypted: reset ids, cap the password
// history, record the folder/collection relationship, cleanup and append.
func (i *JsonImporter) addCipher(result *model.ImportResult, c *cipherExport, cipher *model.CipherView, groupings map[string]int) {
	cipher.ID = ""
	cipher.OrganizationID = ""
	cipher.CollectionIDs = nil
	if len(cipher.PasswordHistory) > 5 {
		cipher.PasswordHistory = cipher.PasswordHistory[:5]
	}

	if !i.Organization() && c.FolderID != nil {
		if idx, ok := groupings[string(*c.FolderID)]; ok {
			result.FolderRelationships = append(result.FolderRelationships, model.Relationship{len(result.Ciphers), idx})
		}
	} else if i.Organization() && c.CollectionIDs != nil {
		for _, id := range c.CollectionIDs {
			if idx, ok := groupings[string(id)]; ok {
				result.CollectionRelationships = append(result.CollectionRelationships, model.Relationship{len(result.Ciphers), idx})
			}
		}
	}

	i.CleanupCipher(cipher)
	result.Ciphers = append(result.Ciphers, cipher)
}
