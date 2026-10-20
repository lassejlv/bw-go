// Package keeper ports libs/importer/src/importers/keeper: the shared KeeperImporter base
// (keeper-importer.ts), the CSV importer (keepercsv) and the JSON importer (keeperjson). The
// unified "keeper" id is resolved to one of them by importer.ResolveFormat; the direct (sign-in)
// importer is not a CLI file format.
package keeper

import (
	"github.com/lassejlv/bw-go/internal/importer"
	"github.com/lassejlv/bw-go/internal/importer/model"
)

func init() {
	importer.Register("keepercsv", NewCsv)
	importer.Register("keeperjson", NewJson)
}

// keeperImporter is KeeperImporter (keeper-importer.ts).
type keeperImporter struct {
	importer.Base
	// useNewDedicatedTypes is configService.getFeatureFlag(FeatureFlag.PM32009NewItemTypes).
	useNewDedicatedTypes bool
}

func newKeeperImporter(opts importer.Options) keeperImporter {
	return keeperImporter{Base: importer.NewBase(opts), useNewDedicatedTypes: opts.Features.NewItemTypes}
}

func (i *keeperImporter) warning(msg string) {
	if i.Warn != nil {
		i.Warn(msg)
		return
	}
	importer.DefaultWarn(msg)
}

// copyLoginPropertiesAsCustomFields is KeeperImporter.copyLoginPropertiesAsCustomFields.
func (i *keeperImporter) copyLoginPropertiesAsCustomFields(cipher *model.CipherView) {
	if !i.IsNullOrWhitespace(cipher.Login.Username) {
		i.addField(cipher, "Username", cipher.Login.Username)
		cipher.Login.Username = ""
	}

	if !i.IsNullOrWhitespace(cipher.Login.Password) {
		i.addField(cipher, "Password", cipher.Login.Password, model.FieldTypeHidden)
		cipher.Login.Password = ""
	}

	if cipher.Login.Uris != nil {
		for _, uri := range cipher.Login.Uris {
			i.addField(cipher, "URL", uri.Uri)
		}
		cipher.Login.Uris = []*model.LoginUriView{}
	}
}

// addField is KeeperImporter.addField for a string value (`if (!value) return`).
func (i *keeperImporter) addField(cipher *model.CipherView, name, value string, fieldType ...model.FieldType) {
	if value == "" {
		return
	}
	t := model.FieldTypeText
	if len(fieldType) > 0 {
		t = fieldType[0]
	}
	cipher.Fields = append(cipher.Fields, &model.FieldView{Type: t, Name: name, Value: value})
}

// addFieldJS is KeeperImporter.addField for an arbitrary JSON value: falsy values are skipped and
// the rest converted with convertToFieldValue.
func (i *keeperImporter) addFieldJS(cipher *model.CipherView, name string, value *jsValue, fieldType ...model.FieldType) {
	if !value.truthy() {
		return
	}
	i.addField(cipher, name, convertToFieldValue(value), fieldType...)
}

// convertToFieldValue is KeeperImporter.convertToFieldValue.
func convertToFieldValue(value *jsValue) string {
	if value != nil && value.kind == jsString {
		return value.s
	}
	if value == nil {
		// JSON.stringify(undefined) is undefined.
		return ""
	}
	return value.stringify()
}
