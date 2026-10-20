package model

// Relationship is the TS tuple [cipherIndex, folderIndex] / [cipherIndex, collectionIndex].
type Relationship [2]int

// CipherIndex returns r[0].
func (r Relationship) CipherIndex() int { return r[0] }

// GroupIndex returns r[1] (the folder or collection index).
func (r Relationship) GroupIndex() int { return r[1] }

// ImportRecordError mirrors import-record-error.ts: an item that was skipped.
type ImportRecordError struct {
	ID     string
	Reason ImportRecordErrorReason
	Type   string
}

// ImportResult mirrors libs/importer/src/models/import-result.ts.
type ImportResult struct {
	Success      bool
	ErrorMessage string
	// MissingPassword is kept for parity with older clients' ImportResult; current importers never
	// set it.
	MissingPassword bool

	Ciphers                 []*CipherView
	Folders                 []*FolderView
	FolderRelationships     []Relationship
	Collections             []*CollectionView
	CollectionRelationships []Relationship

	// TargetFolderIncluded is true when Folders[0] is the pre-existing destination folder.
	TargetFolderIncluded bool
	// TargetCollectionIncluded is true when Collections[0] is the pre-existing destination collection.
	TargetCollectionIncluded bool

	// Errors lists items that were skipped while the rest imported.
	Errors []ImportRecordError

	// ErrorKey is only set by the "upgrade" Bitwarden importers (ImportUpgradeResult.errorKey).
	ErrorKey ImportResultErrorKey
}

// NewImportResult mirrors `new ImportResult()` (all slices empty, not nil).
func NewImportResult() *ImportResult {
	return &ImportResult{
		Ciphers:                 []*CipherView{},
		Folders:                 []*FolderView{},
		FolderRelationships:     []Relationship{},
		Collections:             []*CollectionView{},
		CollectionRelationships: []Relationship{},
		Errors:                  []ImportRecordError{},
	}
}
