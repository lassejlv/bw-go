package importer

// Messages copied verbatim from apps/cli/src/locales/en/messages.json (and the CLI command).
// $FORMAT$ placeholders are substituted by the caller.
const (
	MsgImportFormatError              = "Data is not formatted correctly. Please check your import file and try again."
	MsgImportNothingError             = "Nothing was imported."
	MsgImportUnassignedItemsError     = "File contains unassigned items."
	MsgErrorAssigningTargetCollection = "Error assigning target collection."
	MsgErrorAssigningTargetFolder     = "Error assigning target folder."
	MsgImportEncKeyError              = "Error decrypting the exported file. Your encryption key does not match the encryption key used export the data."
	MsgInvalidFilePassword            = "Invalid file password, please use the password you entered when you created the export file."
	MsgImportUnsupportedKdfSettings   = "This file uses unsupported encryption settings and cannot be imported."
	MsgImportDirectOnlyError          = "$FORMAT$ signs in to the vendor instead of reading a file, so it cannot be imported with the CLI."
	MsgKdbxWrongFileType              = "This file is not a valid KeePass database (.kdbx). Please select a .kdbx file and try again."
	MsgKdbxCorruptOrOutdated          = "Data is not formatted correctly. Please check your import file and try again."
	MsgKdbxFileTooLarge               = "This KeePass database is too large to import."
	MsgProperImporterTypeRequired     = "Proper importer type required."
	MsgImportFileWasEmpty             = "Import file was empty."
	MsgFormatNotProvided              = "`format` was not provided."
	MsgFilepathNotProvided            = "`filepath` was not provided."
	MsgImportPasswordRequired         = "Import file password is required. Provide --passwordfile or --passwordenv, or run interactively."
	// The CLI locale has no "errorImportingMyItemsMultiCollection" entry, so upstream's
	// i18nService.t returns "" there. This wording is ours; the CLI never passes an import target,
	// so the message is unreachable from `bw import`.
	MsgErrorImportingMyItemsMultiCollection = "Items assigned to multiple collections cannot be imported into My Items."
)
