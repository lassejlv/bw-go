package keeper

import (
	"strings"

	"github.com/lassejlv/bw-go/internal/importer"
	"github.com/lassejlv/bw-go/internal/importer/model"
)

// CsvImporter is KeeperCsvImporter (keeper-csv-importer.ts).
type CsvImporter struct{ keeperImporter }

// NewCsv builds the keepercsv importer.
func NewCsv(opts importer.Options) importer.Importer {
	return &CsvImporter{keeperImporter: newKeeperImporter(opts)}
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

// Parse implements importer.Importer.
func (i *CsvImporter) Parse(data string) (*model.ImportResult, error) {
	result := model.NewImportResult()
	results := i.ParseCsvRows(data, nil)
	if results == nil {
		result.Success = false
		return result, nil
	}

	useNewDedicatedTypes := i.useNewDedicatedTypes

	for _, value := range results {
		if len(value) < 6 {
			continue
		}

		i.ProcessFolder(result, value[0])
		cipher := i.InitLoginCipher()

		cipher.Name = i.GetValueOrDefault(value[1], "--")
		cipher.Login.Username = i.GetValueOrDefault(value[2])
		cipher.Login.Password = i.GetValueOrDefault(value[3])
		cipher.Login.Uris = i.MakeUriArray(value[4])
		notes := importer.JSTrimEnd(i.GetValueOrDefault(value[5], ""))
		if len(notes) > 0 {
			cipher.Notes = notes
		}

		// We currently ignore index 6, which is for shared folders

		var customFields []string
		if len(value) > 7 {
			customFields = value[7:]
		}
		// If the above array has any values we have some custom fields, which are listed in the row
		// as [key1, value1, key2, value2, ...]
		var fieldNames []string
		for idx, v := range customFields {
			if idx%2 == 0 {
				fieldNames = append(fieldNames, v)
			}
		}
		bankAccountView := &model.BankAccountView{}
		isBankAccount := contains(fieldNames, "Bank Account")
		passportView := &model.PassportView{}
		isPassport := contains(fieldNames, "Passport Number")
		driversLicenseView := &model.DriversLicenseView{}
		isDriversLicense := contains(fieldNames, "Driver's License Number")

		for idx := 0; idx < len(customFields); idx += 2 {
			fieldName := customFields[idx]
			// customFields[i + 1] is undefined for an odd number of values.
			fieldValue, hasValue := "", idx+1 < len(customFields)
			if hasValue {
				fieldValue = customFields[idx+1]
			}

			if !useNewDedicatedTypes {
				if fieldName == "TFC:Keeper" {
					cipher.Login.Totp = fieldValue
				} else {
					i.ProcessKvp(cipher, fieldName, fieldValue)
				}
				continue
			}

			switch fieldName {
			case "TFC:Keeper":
				cipher.Login.Totp = fieldValue
			// TODO: Currently this relies on English field names.
			// We should add support for other languages later
			case "Bank Account":
				if !hasValue {
					return nil, newTypeError("Cannot read properties of undefined (reading 'split')")
				}
				parts := strings.Split(fieldValue, " | ")
				at := func(n int) string {
					if n < len(parts) {
						return parts[n]
					}
					return ""
				}
				bankAccountView.AccountType = i.ProcessBankAccountType(at(0))
				bankAccountView.AccountNumber = at(1)
				bankAccountView.RoutingNumber = at(2)
			case "Name":
				switch {
				case isBankAccount:
					bankAccountView.NameOnAccount = fieldValue
				case isPassport:
					first, middle, last := i.GetFullName(fieldValue)
					passportView.GivenName = first
					if middle != "" {
						// getFullName's first part is null (not undefined) whenever a middle name exists.
						passportView.GivenName = jsConcatNullable(passportView.GivenName, "null") + " " + middle
					}
					passportView.Surname = last
				case isDriversLicense:
					first, middle, last := i.GetFullName(fieldValue)
					driversLicenseView.FirstName = first
					driversLicenseView.MiddleName = middle
					driversLicenseView.LastName = last
				default:
					i.ProcessKvp(cipher, fieldName, fieldValue)
				}
			case "Passport Number":
				passportView.PassportNumber = fieldValue
			case "Driver's License Number":
				driversLicenseView.LicenseNumber = fieldValue
			case "Date of Birth":
				switch {
				case isPassport:
					passportView.DateOfBirth = i.parseKeeperCsvDateString(fieldValue)
				case isDriversLicense:
					driversLicenseView.DateOfBirth = i.parseKeeperCsvDateString(fieldValue)
				default:
					i.ProcessKvp(cipher, fieldName, fieldValue)
				}
			case "Date":
				switch {
				case isPassport:
					passportView.ExpirationDate = i.parseKeeperCsvDateString(fieldValue)
				case isDriversLicense:
					driversLicenseView.ExpirationDate = i.parseKeeperCsvDateString(fieldValue)
				default:
					i.ProcessKvp(cipher, fieldName, fieldValue)
				}
			case "Date Issued":
				if isPassport {
					passportView.IssueDate = i.parseKeeperCsvDateString(fieldValue)
				} else {
					i.ProcessKvp(cipher, fieldName, fieldValue)
				}
			default:
				i.ProcessKvp(cipher, fieldName, fieldValue)
			}
		}

		if useNewDedicatedTypes && isPassport {
			cipher.Type = model.CipherTypePassport
			cipher.Passport = passportView
			i.copyLoginPropertiesAsCustomFields(cipher)
		} else if useNewDedicatedTypes && isDriversLicense {
			cipher.Type = model.CipherTypeDriversLicense
			cipher.DriversLicense = driversLicenseView
			i.copyLoginPropertiesAsCustomFields(cipher)
		}

		i.CleanupCipher(cipher)
		result.Ciphers = append(result.Ciphers, cipher)

		if useNewDedicatedTypes && isBankAccount {
			bankAccountCipher := i.InitLoginCipher()
			bankAccountCipher.Name = cipher.Name
			bankAccountCipher.Type = model.CipherTypeBankAccount
			bankAccountCipher.BankAccount = bankAccountView
			i.CleanupCipher(bankAccountCipher)
			// Make sure the bank account is in the same folder as the login cipher. This
			// must happen before the cipher is pushed to the results to get the right index
			i.ProcessFolder(result, value[0])
			result.Ciphers = append(result.Ciphers, bankAccountCipher)
		}
	}

	if i.Organization() {
		i.MoveFoldersToCollections(result)
	}

	result.Success = true
	return result, nil
}

// jsConcatNullable renders a nullable string the way `a + " " + b` does in JavaScript: a null or
// undefined part becomes its name.
func jsConcatNullable(s, nullName string) string {
	if s == "" {
		return nullName
	}
	return s
}

// parseKeeperCsvDateString is KeeperCsvImporter.parseKeeperCsvDateString: Keeper CSV dates are
// formatted as `MM/DD/YYYY`.
func (i *CsvImporter) parseKeeperCsvDateString(dateString string) string {
	if i.IsNullOrWhitespace(dateString) {
		return ""
	}
	parts := strings.Split(dateString, "/")
	at := func(n int) string {
		if n < len(parts) {
			return parts[n]
		}
		return ""
	}
	month, day, year := at(0), at(1), at(2)
	if i.IsNullOrWhitespace(year) || i.IsNullOrWhitespace(month) || i.IsNullOrWhitespace(day) {
		return ""
	}
	return year + "-" + padStart2(month) + "-" + padStart2(day)
}

// padStart2 is s.padStart(2, "0") (UTF-16 length).
func padStart2(s string) string {
	switch importer.Len16(s) {
	case 0:
		return "00"
	case 1:
		return "0" + s
	}
	return s
}
