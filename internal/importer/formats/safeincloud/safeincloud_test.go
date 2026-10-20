package safeincloud

import (
	"testing"

	"github.com/lassejlv/bw-go/internal/importer/importertest"
	"github.com/lassejlv/bw-go/internal/importer/model"
)

// Ported from libs/importer/src/importers/safeincloud-xml-importer.spec.ts. testdata/data.txt was
// extracted from spec-data/safeincloud/test-data.xml.ts.

const multipleLoginsXml = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<database>
    <card title="Server" id="500" autofill="on">
        <field name="Primary login" type="login" autofill="username">primary@example.com</field>
        <field name="Secondary login" type="login" autofill="username">secondary@example.com</field>
        <field name="Password" type="password" autofill="current-password">hunter2</field>
    </card>
</database>
`

func parse(t *testing.T, data string) *model.ImportResult {
	return importertest.Parse(t, New(importertest.Options()), data)
}

func fixture(t *testing.T) *model.ImportResult { return parse(t, importertest.ReadFile(t, "data.txt")) }

func find(t *testing.T, r *model.ImportResult, name string) *model.CipherView {
	t.Helper()
	for _, c := range r.Ciphers {
		if c.Name == name {
			return c
		}
	}
	t.Fatalf("cipher %q not found", name)
	return nil
}

func field(c *model.CipherView, name string) *model.FieldView {
	for _, f := range c.Fields {
		if f.Name == name {
			return f
		}
	}
	return nil
}

func TestFixture(t *testing.T) {
	r := fixture(t)
	// Templates (id=102), deleted (Facebook id=301), and ghosts are excluded; 6 cards remain.
	if !r.Success || len(r.Ciphers) != 6 {
		t.Fatalf("%v %d", r.Success, len(r.Ciphers))
	}
	// Labels do not create folders.
	if len(r.Folders) != 0 || len(r.FolderRelationships) != 0 {
		t.Fatal("folders created")
	}
}

func TestBOMAndLeadingWhitespace(t *testing.T) {
	r := parse(t, "\uFEFF \n"+multipleLoginsXml)
	if !r.Success || len(r.Ciphers) != 1 {
		t.Fatalf("%s", importertest.Dump(r))
	}
}

func TestMissingDatabase(t *testing.T) {
	r := parse(t, `<?xml version="1.0"?><root></root>`)
	if r.Success || r.ErrorMessage != "Missing `database` node." {
		t.Fatalf("%v %q", r.Success, r.ErrorMessage)
	}
}

func TestCreditCard(t *testing.T) {
	visa := find(t, fixture(t), "Visa Card (Sample)")
	if visa.Type != model.CipherTypeCard || visa.Login != nil {
		t.Fatalf("%s", importertest.Dump(visa))
	}
	c := visa.Card
	if c.Number != "5555123456789000" || c.Brand != "Mastercard" || c.CardholderName != "John Smith" ||
		c.ExpMonth != "1" || c.ExpYear != "2023" || c.Code != "555" {
		t.Fatalf("%s", importertest.Dump(c))
	}
	pin := field(visa, "PIN")
	if pin == nil || pin.Value != "1111" || pin.Type != model.FieldTypeHidden {
		t.Fatalf("pin %s", importertest.Dump(pin))
	}
	if field(visa, "CVV") != nil {
		t.Fatal("CVV exposed as a custom field")
	}
}

func TestMultipleLogins(t *testing.T) {
	r := parse(t, multipleLoginsXml)
	if !r.Success {
		t.Fatal("parse")
	}
	c := r.Ciphers[0]
	if c.Type != model.CipherTypeLogin || c.Login.Username != "primary@example.com" || c.Login.Password != "hunter2" {
		t.Fatalf("%s", importertest.Dump(c))
	}
	extra := field(c, "Secondary login")
	if extra == nil || extra.Value != "secondary@example.com" || extra.Type != model.FieldTypeText {
		t.Fatalf("%s", importertest.Dump(extra))
	}
	// "Password" is a password field name, so it is removed from the custom fields.
	if field(c, "Password") != nil {
		t.Fatal("password field kept")
	}
}

func TestSecretHidden(t *testing.T) {
	google := find(t, fixture(t), "Google (Sample)")
	secret := field(google, "2FA-Reset")
	if secret == nil || secret.Value != "thisshouldbehidden" || secret.Type != model.FieldTypeHidden {
		t.Fatalf("%s", importertest.Dump(secret))
	}
	if google.Login.Totp != "thisisanotp" {
		t.Fatalf("totp %q", google.Login.Totp)
	}
}

func TestPasswordPromoted(t *testing.T) {
	twitter := find(t, fixture(t), "Twitter (Sample)")
	if twitter.Type != model.CipherTypeLogin || twitter.Login.Password != "shouldbepassword" {
		t.Fatalf("%s", importertest.Dump(twitter))
	}
}
