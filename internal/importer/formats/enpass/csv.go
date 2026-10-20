// Package enpass ports libs/importer/src/importers/enpass: the Enpass CSV importer
// (enpass-csv-importer.ts, format id "enpasscsv") and the Enpass JSON importer
// (enpass-json-importer.ts, format id "enpassjson").
package enpass

import (
	"strings"

	"github.com/lassejlv/bw-go/internal/importer"
	"github.com/lassejlv/bw-go/internal/importer/model"
)

func init() {
	importer.Register("enpasscsv", NewCsv)
	importer.Register("enpassjson", NewJson)
}

// CsvImporter is EnpassCsvImporter.
type CsvImporter struct{ importer.Base }

// NewCsv constructs an EnpassCsvImporter.
func NewCsv(opts importer.Options) importer.Importer {
	return &CsvImporter{Base: importer.NewBase(opts)}
}

// Parse is EnpassCsvImporter.parse.
func (i *CsvImporter) Parse(data string) (*model.ImportResult, error) {
	result := model.NewImportResult()
	results := i.ParseCsvRows(data, nil)
	if results == nil {
		result.Success = false
		return result, nil
	}

	firstRow := true
	for _, value := range results {
		if len(value) < 2 || (firstRow && (value[0] == "Title" || value[0] == "title")) {
			firstRow = false
			continue
		}

		cipher := i.InitLoginCipher()
		cipher.Name = i.GetValueOrDefault(value[0], "--")

		// Enpass appends a note as an unpaired trailing column, making the row length even
		hasTrailingNote := len(value)%2 == 0
		if hasTrailingNote {
			cipher.Notes = i.GetValueOrDefault(value[len(value)-1])
		}

		// Field labels live at odd indices below pairsEnd; excludes the title and the trailing note
		pairsEnd := len(value)
		if hasTrailingNote {
			pairsEnd = len(value) - 1
		}
		var labels []string
		for idx, v := range value {
			if idx%2 == 1 && idx < pairsEnd {
				labels = append(labels, v)
			}
		}

		if len(value) == 2 ||
			(!i.containsField(labels, "username") &&
				!i.containsField(labels, "password") &&
				!i.containsField(labels, "email") &&
				!i.containsField(labels, "e-mail") &&
				!i.containsField(labels, "url") &&
				!i.containsField(labels, "website")) {
			cipher.Type = model.CipherTypeSecureNote
			cipher.SecureNote = &model.SecureNoteView{Type: model.SecureNoteTypeGeneric}
		}

		if i.containsField(labels, "cardholder") &&
			i.containsField(labels, "number") &&
			i.containsField(labels, "expiry date") {
			cipher.Type = model.CipherTypeCard
			cipher.Card = &model.CardView{}
		}

		if pairsEnd > 2 {
			for j := 0; j < pairsEnd-1; j += 2 {
				fieldValue := value[j+2]
				if i.IsNullOrWhitespace(fieldValue) {
					continue
				}

				fieldName := value[j+1]
				fieldNameLower := i.normalizeFieldName(fieldName)

				if cipher.Type == model.CipherTypeLogin {
					if fieldNameLower == "url" || fieldNameLower == "website" {
						// Enpass exports a primary Website plus a sign-in/change-password Website;
						// both become login URIs so autofill matches either domain
						uris := i.MakeUriArray(fieldValue)
						if uris != nil {
							cipher.Login.Uris = append(cipher.Login.Uris, uris...)
						}
						continue
					} else if (fieldNameLower == "username" || fieldNameLower == "email" || fieldNameLower == "e-mail") &&
						i.IsNullOrWhitespace(cipher.Login.Username) {
						cipher.Login.Username = fieldValue
						continue
					} else if fieldNameLower == "password" && i.IsNullOrWhitespace(cipher.Login.Password) {
						cipher.Login.Password = fieldValue
						continue
					} else if (fieldNameLower == "totp" || fieldNameLower == "one-time code") &&
						i.IsNullOrWhitespace(cipher.Login.Totp) {
						cipher.Login.Totp = fieldValue
						continue
					}
				} else if cipher.Type == model.CipherTypeCard {
					if fieldNameLower == "cardholder" && i.IsNullOrWhitespace(cipher.Card.CardholderName) {
						cipher.Card.CardholderName = fieldValue
						continue
					} else if fieldNameLower == "number" && i.IsNullOrWhitespace(cipher.Card.Number) {
						cipher.Card.Number = fieldValue
						cipher.Card.Brand = model.GetCardBrandByPatterns(cipher.Card.Number)
						continue
					} else if fieldNameLower == "cvc" && i.IsNullOrWhitespace(cipher.Card.Code) {
						cipher.Card.Code = fieldValue
						continue
					} else if fieldNameLower == "expiry date" &&
						i.IsNullOrWhitespace(cipher.Card.ExpMonth) &&
						i.IsNullOrWhitespace(cipher.Card.ExpYear) {
						if i.SetCardExpiration(cipher, fieldValue) {
							continue
						}
					} else if fieldNameLower == "type" {
						// Skip since brand was determined from number above
						continue
					}
				}

				// '*' marks a sensitive Enpass field; strip it from the display name and mask the value
				isSensitiveField := strings.HasPrefix(fieldName, "*")
				name, fieldType := fieldName, model.FieldTypeText
				if isSensitiveField {
					name, fieldType = importer.JSTrim(fieldName[1:]), model.FieldTypeHidden
				}
				i.ProcessKvp(cipher, name, fieldValue, fieldType)
			}
		}

		i.CleanupCipher(cipher)
		result.Ciphers = append(result.Ciphers, cipher)
	}

	result.Success = true
	return result, nil
}

func (i *CsvImporter) containsField(fields []string, name string) bool {
	if fields == nil {
		return false
	}
	for _, f := range fields {
		if !i.IsNullOrWhitespace(f) && i.normalizeFieldName(f) == strings.ToLower(name) {
			return true
		}
	}
	return false
}

// normalizeFieldName: Enpass prefixes sensitive field labels (e.g. Password, Security answer)
// with '*'.
func (i *CsvImporter) normalizeFieldName(name string) string {
	if i.IsNullOrWhitespace(name) {
		return ""
	}
	return strings.ToLower(importer.JSTrim(strings.TrimPrefix(name, "*")))
}
