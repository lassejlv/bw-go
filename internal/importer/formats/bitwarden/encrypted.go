package bitwarden

import (
	"errors"

	"github.com/lassejlv/bw-go/internal/crypto"
	"github.com/lassejlv/bw-go/internal/importer"
	"github.com/lassejlv/bw-go/internal/importer/model"
)

// decryptErrorText is what a failed EncString.decrypt yields in the TS domain models.
const decryptErrorText = "[error: cannot decrypt]"

// ErrNoDecryptor is returned when an account-encrypted export is imported without
// Options.Decryptor.
var ErrNoDecryptor = errors.New("importing an account-encrypted export requires an unlocked vault")

// EncryptedJsonImporter is BitwardenEncryptedJsonImporter: account-restricted ("encrypted")
// exports, decrypted with the account's user key or the target organization's key.
type EncryptedJsonImporter struct {
	JsonImporter
	decryptor importer.Decryptor
	// upgrade selects UpgradeBitwardenEncryptedJsonImporter behaviour (errorKey on failures).
	upgrade bool
}

// NewEncryptedJson constructs the account-encrypted importer.
func NewEncryptedJson(opts importer.Options) *EncryptedJsonImporter {
	return &EncryptedJsonImporter{JsonImporter: *NewJson(opts), decryptor: opts.Decryptor}
}

// Parse implements importer.Importer.
func (i *EncryptedJsonImporter) Parse(data string) (*model.ImportResult, error) {
	results, err := parseExportFile(data)
	if err != nil {
		return nil, err
	}
	if results != nil && results.isPasswordProtected() {
		return nil, errors.New("Data is password-protected. Use BitwardenPasswordProtectedImporter instead.")
	}
	if results == nil || results.Items == nil {
		r := model.NewImportResult()
		r.Success = false
		return r, nil
	}
	if results.isUnencrypted() {
		return i.JsonImporter.Parse(data)
	}
	return i.parseEncrypted(results)
}

func (i *EncryptedJsonImporter) fail(result *model.ImportResult, key model.ImportResultErrorKey) *model.ImportResult {
	result.Success = false
	result.ErrorMessage = importer.MsgImportEncKeyError
	if i.upgrade && key != "" {
		result.ErrorKey = key
	}
	return result
}

func (i *EncryptedJsonImporter) parseEncrypted(data *exportFile) (*model.ImportResult, error) {
	result := model.NewImportResult()
	if i.decryptor == nil {
		return nil, ErrNoDecryptor
	}

	encKeyValidation := rawString(data.EncKeyValidation)
	if importer.IsNullOrWhitespace(encKeyValidation) {
		return i.fail(result, ""), nil
	}

	var keyForDecryption *crypto.SymmetricKey
	if i.Organization() {
		k, err := i.decryptor.OrgKey(i.OrganizationID)
		if err == nil {
			keyForDecryption = k
		}
	}
	if keyForDecryption == nil {
		k, err := i.decryptor.UserKey()
		if err == nil {
			keyForDecryption = k
		}
	}
	if keyForDecryption == nil {
		return i.fail(result, ""), nil
	}
	if _, err := crypto.DecryptString(encKeyValidation, keyForDecryption); err != nil {
		return i.fail(result, model.ImportResultErrorKeyAccountMismatch), nil
	}

	groupings := map[string]int{}
	if data.Collections != nil { // isOrgEncrypted
		for _, c := range data.Collections {
			name := decryptErrorText
			if orgKey, err := i.decryptor.OrgKey(string(c.OrganizationID)); err == nil && orgKey != nil {
				if v, err := crypto.DecryptString(string(c.Name), orgKey); err == nil {
					name = v
				}
			}
			groupings[string(c.ID)] = len(result.Collections)
			result.Collections = append(result.Collections, &model.CollectionView{
				ID: string(c.ID), OrganizationID: i.OrganizationID, Name: name, ExternalID: string(c.ExternalID),
			})
		}
	} else if data.Folders != nil {
		userKey, _ := i.decryptor.UserKey()
		for _, f := range data.Folders {
			name := decryptErrorText
			if userKey != nil {
				if v, err := crypto.DecryptString(string(f.Name), userKey); err == nil {
					name = v
				}
			}
			groupings[string(f.ID)] = len(result.Folders)
			result.Folders = append(result.Folders, &model.FolderView{ID: string(f.ID), Name: name})
		}
	}

	for _, raw := range data.Items {
		c, err := parseCipherExport(raw)
		if err != nil {
			return nil, err
		}
		view, err := i.decryptor.DecryptExportCipher(raw, i.OrganizationID)
		if err != nil {
			return nil, err
		}
		i.addCipher(result, c, view, groupings)
		view.OrganizationID = i.OrganizationID
	}

	result.Success = true
	return result, nil
}
