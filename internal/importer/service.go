package importer

import (
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/lassejlv/bw-go/internal/importer/model"
)

// ImportTarget is the `selectedImportTarget` of ImportService.import: a folder for an individual
// import or a collection for an organization import. The CLI never sets one.
type ImportTarget struct {
	Folder     *model.FolderView
	Collection *model.CollectionView
}

// ImportParams are the arguments of ImportService.import/importImportResult that do not need the
// vault.
type ImportParams struct {
	// OrganizationID is the target organization ("" = individual vault).
	OrganizationID string
	// Target is the optional destination folder/collection (nil for the CLI).
	Target *ImportTarget
	// CanAccessImportExport is the permission flag. Upstream's CLI does not pass it, so it is
	// false for `bw import`.
	CanAccessImportExport bool
	// RestrictedTypes are the cipher types the organization policy forbids
	// (RestrictedItemTypesService.restricted$); ciphers of these types are dropped.
	RestrictedTypes []model.CipherType
}

// Import is the parsing half of ImportService.import: it runs the importer (mapping syntax errors
// to "importFormatError") and then Prepare. The caller encrypts the result and posts it (see
// README.md "What the import command must do").
func Import(imp Importer, fileContents string, p ImportParams) (*model.ImportResult, error) {
	result, err := imp.Parse(fileContents)
	if err != nil {
		if IsSyntaxError(err) {
			return nil, errors.New(MsgImportFormatError)
		}
		return nil, err
	}
	if err := Prepare(result, p); err != nil {
		return nil, err
	}
	return result, nil
}

// Prepare is ImportService.importImportResult up to (and including) setImportTarget: it validates
// the result, filters restricted item types, enforces the organization "unassigned items" rule and
// applies the import target. Everything after that (encrypting and POSTing) is left to the
// caller.
func Prepare(result *model.ImportResult, p ImportParams) error {
	if result == nil {
		return errors.New(MsgImportFormatError)
	}
	if !result.Success {
		if !IsNullOrWhitespace(result.ErrorMessage) {
			return errors.New(result.ErrorMessage)
		}
		return errors.New(MsgImportFormatError)
	}
	if len(result.Folders) == 0 && len(result.Ciphers) == 0 {
		return errors.New(MsgImportNothingError)
	}
	if n := len(result.Ciphers); n > 0 {
		halfway, last := n/2, n-1
		if badData(result.Ciphers[0]) && badData(result.Ciphers[halfway]) && badData(result.Ciphers[last]) {
			return errors.New(MsgImportFormatError)
		}
	}

	// Upstream filters ciphers without re-indexing the relationships, which can attach the
	// remaining items to the wrong folder or collection; DropRestrictedTypes keeps them aligned.
	DropRestrictedTypes(result, p.RestrictedTypes)

	if p.OrganizationID != "" && p.Target == nil && !p.CanAccessImportExport {
		if len(result.CollectionRelationships) < len(result.Ciphers) {
			return errors.New(MsgImportUnassignedItemsError)
		}
	}
	return SetImportTarget(result, p.OrganizationID, p.Target)
}

// DropRestrictedTypes removes ciphers of the given types and re-indexes the folder and
// collection relationships of the remaining ciphers.
func DropRestrictedTypes(result *model.ImportResult, restricted []model.CipherType) {
	if len(restricted) == 0 {
		return
	}
	newIndex := make([]int, len(result.Ciphers))
	kept := result.Ciphers[:0:0]
	for i, c := range result.Ciphers {
		newIndex[i] = -1
		if !slices.Contains(restricted, c.Type) {
			newIndex[i] = len(kept)
			kept = append(kept, c)
		}
	}
	remap := func(rels []model.Relationship) []model.Relationship {
		out := rels[:0:0]
		for _, r := range rels {
			if r[0] >= 0 && r[0] < len(newIndex) && newIndex[r[0]] >= 0 {
				out = append(out, model.Relationship{newIndex[r[0]], r[1]})
			}
		}
		return out
	}
	result.Ciphers = kept
	result.FolderRelationships = remap(result.FolderRelationships)
	result.CollectionRelationships = remap(result.CollectionRelationships)
}

// badData is ImportService.badData.
func badData(c *model.CipherView) bool {
	return (c.Name == "" || c.Name == "--") && c.Type == model.CipherTypeLogin && c.Login != nil &&
		IsNullOrWhitespace(c.Login.Password)
}

// SetImportTarget is ImportService.setImportTarget.
func SetImportTarget(result *model.ImportResult, organizationID string, target *ImportTarget) error {
	if target == nil || (target.Folder == nil && target.Collection == nil) {
		return nil
	}

	if organizationID != "" {
		if target.Collection == nil {
			return errors.New(MsgErrorAssigningTargetCollection)
		}
		importTarget := target.Collection

		var noCollection []model.Relationship
		for i := range result.Ciphers {
			found := false
			for _, r := range result.CollectionRelationships {
				if r[0] == i {
					found = true
					break
				}
			}
			if !found {
				noCollection = append(noCollection, model.Relationship{i, 0})
			}
		}

		if importTarget.Type == model.CollectionTypeDefaultUserCollection {
			if len(result.Folders) > 0 {
				// Individual vault export: preserve folders.
				for i, c := range result.Ciphers {
					for fi, f := range result.Folders {
						if f.ID == c.FolderID {
							result.FolderRelationships = append(result.FolderRelationships, model.Relationship{i, fi})
							break
						}
					}
				}
			} else {
				// Organization export: turn collections into folders (one per cipher max).
				for ci := range result.Ciphers {
					n := 0
					for _, cr := range result.CollectionRelationships {
						if cr[0] == ci {
							n++
						}
					}
					if n > 1 {
						return errors.New(MsgErrorImportingMyItemsMultiCollection)
					}
				}
				folders := make([]*model.FolderView, 0, len(result.Collections))
				for _, c := range result.Collections {
					folders = append(folders, &model.FolderView{Name: c.Name})
				}
				result.Folders = folders
				rels := make([]model.Relationship, 0, len(result.CollectionRelationships))
				rels = append(rels, result.CollectionRelationships...)
				result.FolderRelationships = rels
			}
			result.Collections = []*model.CollectionView{importTarget}
			result.TargetCollectionIncluded = true
			rels := make([]model.Relationship, 0, len(result.Ciphers))
			for i := range result.Ciphers {
				rels = append(rels, model.Relationship{i, 0})
			}
			result.CollectionRelationships = rels
			return nil
		}

		collections := result.Collections
		result.Collections = []*model.CollectionView{importTarget}
		result.TargetCollectionIncluded = true
		for _, x := range collections {
			c := *x
			c.Name = importTarget.Name + "/" + x.Name
			result.Collections = append(result.Collections, &c)
		}
		relationships := result.CollectionRelationships
		result.CollectionRelationships = append([]model.Relationship{}, noCollection...)
		for _, x := range relationships {
			result.CollectionRelationships = append(result.CollectionRelationships, model.Relationship{x[0], x[1] + 1})
		}
		return nil
	}

	if target.Folder == nil {
		return errors.New(MsgErrorAssigningTargetFolder)
	}
	importTarget := target.Folder

	var noFolder []model.Relationship
	for i, c := range result.Ciphers {
		found := false
		for _, r := range result.FolderRelationships {
			if r[0] == i {
				found = true
				break
			}
		}
		if !found {
			c.FolderID = importTarget.ID
			noFolder = append(noFolder, model.Relationship{i, 0})
		}
	}
	folders := result.Folders
	result.Folders = []*model.FolderView{importTarget}
	result.TargetFolderIncluded = true
	for _, x := range folders {
		result.Folders = append(result.Folders, &model.FolderView{Name: importTarget.Name + "/" + x.Name})
	}
	relationships := result.FolderRelationships
	result.FolderRelationships = append([]model.Relationship{}, noFolder...)
	for _, x := range relationships {
		result.FolderRelationships = append(result.FolderRelationships, model.Relationship{x[0], x[1] + 1})
	}
	return nil
}

// ValidationError is one entry of an ErrorResponse's validationErrors, in server order.
type ValidationError struct {
	Key      string
	Messages []string
}

var (
	firstNumberRe = regexp.MustCompile(`[0-9]+`)
	firstWordRe   = regexp.MustCompile(`^\w+`)
)

// ServerError is ImportService.handleServerError: it turns the server's validation errors for a
// failed POST /ciphers/import[-organization] into the message upstream shows, e.g.
// `[1] [Login] "Item name": The field Name must be ...`. With no validation errors the plain
// error message is returned.
func ServerError(message string, validationErrors []ValidationError, result *model.ImportResult) error {
	if validationErrors == nil {
		return errors.New(message)
	}
	var b strings.Builder
	for index, ve := range validationErrors {
		numStr := firstNumberRe.FindString(ve.Key)
		word := firstWordRe.FindString(ve.Key)
		i, _ := strconv.Atoi(numStr)
		var name, itemType string
		switch word {
		case "Ciphers":
			if i >= len(result.Ciphers) {
				continue
			}
			name, itemType = result.Ciphers[i].Name, result.Ciphers[i].Type.Name()
		case "Folders":
			if i >= len(result.Folders) {
				continue
			}
			name, itemType = result.Folders[i].Name, "Folder"
		case "Collections":
			if i >= len(result.Collections) {
				continue
			}
			name, itemType = result.Collections[i].Name, "Collection"
		default:
			continue
		}
		if index > 0 {
			b.WriteString("\n\n")
		}
		if itemType != "Folder" && itemType != "Collection" {
			fmt.Fprintf(&b, "[%d] ", i+1)
		}
		fmt.Fprintf(&b, "[%s] \"%s\": %s", itemType, name, strings.Join(ve.Messages, ","))
	}
	return errors.New(b.String())
}

// ImportErrorReasonText is ImportCommand.importErrorReasonText.
func ImportErrorReasonText(reason model.ImportRecordErrorReason) string {
	switch reason {
	case model.ImportRecordErrorReasonSshKeyParseFailed:
		return "SSH key could not be imported"
	case model.ImportRecordErrorReasonUnsupportedType:
		return "unsupported item type"
	case model.ImportRecordErrorReasonUnsupportedFeature:
		return "unsupported feature"
	case model.ImportRecordErrorReasonFolderDecryptionFailed:
		return "folder could not be decrypted"
	}
	return "could not be imported"
}

// SkippedItemsMessage is the message ImportCommand.import shows (as MessageResponse.message and
// raw) when a successful import skipped items; "" when nothing was skipped.
func SkippedItemsMessage(skipped []model.ImportRecordError) string {
	if len(skipped) == 0 {
		return ""
	}
	lines := make([]string, 0, len(skipped))
	for _, e := range skipped {
		id := e.ID
		if IsNullOrWhitespace(id) {
			id = "(unidentified item)"
		}
		lines = append(lines, "  - "+id+": "+ImportErrorReasonText(e.Reason))
	}
	return strconv.Itoa(len(skipped)) + " item(s) could not be imported and were skipped:\n" + strings.Join(lines, "\n")
}
