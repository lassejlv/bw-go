package vault

import (
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"time"

	"github.com/lassejlv/bw-go/internal/cli"
	"github.com/lassejlv/bw-go/internal/crypto"
)

// Encryption mirrors the SDK's CipherView encryption (EncryptMode::Legacy / ::Blob) after the TS
// CipherView.toSdkCipherView conversion. A per-cipher key is always used: the view's existing key
// is kept, otherwise a new AES-256-CBC-HMAC key is generated (load_cipher_key_slot).

// ErrEncryptPartial mirrors CryptoError::EncryptRestrictedView.
var ErrEncryptPartial = errors.New("cannot encrypt a restricted (partial) cipher view")

func encStr(p *string, key *crypto.SymmetricKey) (*string, error) {
	if p == nil {
		return nil, nil
	}
	s, err := crypto.EncryptString(*p, key)
	if err != nil {
		return nil, err
	}
	return &s, nil
}

// emptyToNil mirrors `value || undefined`.
func emptyToNil(p *string) *string {
	if p == nil || *p == "" {
		return nil
	}
	return p
}

func cliDate(t *time.Time) *cli.Date {
	if t == nil {
		return nil
	}
	return &cli.Date{Time: *t}
}

// EncryptCipher encrypts a view into an encrypted Cipher. It returns the cipher and the plain
// per-cipher key that was used (generated when the view had none).
func EncryptCipher(v *CipherView, keys *Keys) (*Cipher, *crypto.SymmetricKey, error) {
	if v.Partial {
		return nil, nil, ErrEncryptPartial
	}
	owner, err := keys.OwnerKey(v.OrganizationID)
	if err != nil {
		return nil, nil, err
	}
	cipherKey := v.Key
	if cipherKey == nil {
		cipherKey = crypto.GenerateKey()
	}
	wrapped, err := wrapKey(cipherKey, owner)
	if err != nil {
		return nil, nil, err
	}
	c := &Cipher{
		ID:                  v.ID,
		OrganizationID:      clonePtr(v.OrganizationID),
		FolderID:            clonePtr(v.FolderID),
		Type:                v.Type,
		Favorite:            v.Favorite,
		Edit:                v.Edit,
		ViewPassword:        &v.ViewPassword,
		OrganizationUseTotp: v.OrganizationUseTotp,
		RevisionDate:        &cli.Date{Time: v.RevisionDate},
		CreationDate:        &cli.Date{Time: v.CreationDate},
		DeletedDate:         cliDate(v.DeletedDate),
		ArchivedDate:        cliDate(v.ArchivedDate),
		CollectionIDs:       append([]string{}, v.CollectionIDs...),
		Reprompt:            v.Reprompt,
		Key:                 &wrapped,
	}
	if v.Permissions != nil {
		p := *v.Permissions
		c.Permissions = &p
	}
	if c.Attachments, err = encryptAttachments(v.Attachments, cipherKey); err != nil {
		return nil, nil, err
	}

	if keys.SecurityVersion >= 2 && (v.OrganizationID == nil || *v.OrganizationID == "") {
		blob, err := blobFromView(v)
		if err != nil {
			return nil, nil, err
		}
		data, err := encodeBlob(blob, cipherKey)
		if err != nil {
			return nil, nil, err
		}
		c.Data = FlexString{Val: &data}
		return c, cipherKey, nil
	}

	if err := encryptLegacyFields(v, c, cipherKey); err != nil {
		return nil, nil, err
	}
	return c, cipherKey, nil
}

func encryptLegacyFields(v *CipherView, c *Cipher, key *crypto.SymmetricKey) error {
	var err error
	e := func(p *string) *string {
		if err != nil {
			return nil
		}
		var out *string
		out, err = encStr(p, key)
		return out
	}
	name := v.Name
	c.Name = e(&name)
	c.Notes = e(v.Notes)
	switch v.Type {
	case CipherTypeLogin:
		if l := v.Login; l != nil {
			d := &LoginData{
				Username:             e(emptyToNil(l.Username)),
				Password:             e(emptyToNil(l.Password)),
				PasswordRevisionDate: cliDate(l.PasswordRevisionDate),
				AutofillOnPageLoad:   l.AutofillOnPageLoad,
			}
			if l.HasTotp() {
				d.Totp = e(l.Totp)
			}
			d.URIs = []LoginURIData{}
			for _, u := range l.URIs {
				ud := LoginURIData{URI: e(u.URI), Match: u.Match}
				if u.URI != nil {
					h := sha256.Sum256([]byte(*u.URI))
					sum := base64.StdEncoding.EncodeToString(h[:])
					ud.URIChecksum = e(&sum)
				}
				d.URIs = append(d.URIs, ud)
			}
			if len(l.Fido2Credentials) > 0 {
				for _, f := range l.Fido2Credentials {
					disc := "false"
					if f.Discoverable {
						disc = "true"
					}
					counter := f.Counter
					fd := Fido2CredentialData{
						CredentialID: e(&f.CredentialID), KeyType: e(&f.KeyType), KeyAlgorithm: e(&f.KeyAlgorithm),
						KeyCurve: e(&f.KeyCurve), KeyValue: e(&f.KeyValue), RpID: e(&f.RpID),
						UserHandle: e(f.UserHandle), UserName: e(f.UserName), Counter: e(&counter),
						RpName: e(f.RpName), UserDisplayName: e(f.UserDisplayName), Discoverable: e(&disc),
						CreationDate: cliDate(f.CreationDate),
					}
					d.Fido2Credentials = append(d.Fido2Credentials, fd)
				}
			}
			c.Login = d
		}
	case CipherTypeSecureNote:
		t := SecureNoteTypeGeneric
		if v.SecureNote != nil {
			t = v.SecureNote.Type
		}
		c.SecureNote = &SecureNoteData{Type: t}
	case CipherTypeCard:
		if d := v.Card; d != nil {
			c.Card = &CardData{CardholderName: e(d.CardholderName), Brand: e(d.Brand), Number: e(d.Number),
				ExpMonth: e(d.ExpMonth), ExpYear: e(d.ExpYear), Code: e(d.Code)}
		}
	case CipherTypeIdentity:
		if d := v.Identity; d != nil {
			n := func(p *string) *string { return e(emptyToNil(p)) }
			c.Identity = &IdentityData{Title: n(d.Title), FirstName: n(d.FirstName), MiddleName: n(d.MiddleName),
				LastName: n(d.LastName), Address1: n(d.Address1), Address2: n(d.Address2), Address3: n(d.Address3),
				City: n(d.City), State: n(d.State), PostalCode: n(d.PostalCode), Country: n(d.Country),
				Company: n(d.Company), Email: n(d.Email), Phone: n(d.Phone), SSN: n(d.SSN),
				Username: n(d.Username), PassportNumber: n(d.PassportNumber), LicenseNumber: n(d.LicenseNumber)}
		}
	case CipherTypeSshKey:
		if d := v.SshKey; d != nil {
			pub, fp := d.PublicKey, d.KeyFingerprint
			if pub == "" || fp == "" {
				dp, dfp := deriveSSHPublicKeyAndFingerprint(d.PrivateKey)
				if pub == "" {
					pub = dp
				}
				if fp == "" {
					fp = dfp
				}
			}
			priv := d.PrivateKey
			c.SshKey = &SshKeyData{PrivateKey: e(&priv), PublicKey: e(&pub), KeyFingerprint: e(&fp)}
		}
	case CipherTypeBankAccount:
		if d := v.BankAccount; d != nil {
			c.BankAccount = &BankAccountData{BankName: e(d.BankName), NameOnAccount: e(d.NameOnAccount),
				AccountType: e(d.AccountType), AccountNumber: e(d.AccountNumber), RoutingNumber: e(d.RoutingNumber),
				BranchNumber: e(d.BranchNumber), Pin: e(d.Pin), SwiftCode: e(d.SwiftCode), Iban: e(d.Iban),
				BankContactPhone: e(d.BankContactPhone)}
		}
	case CipherTypeDriversLicense:
		if d := v.DriversLicense; d != nil {
			c.DriversLicense = &DriversLicenseData{FirstName: e(d.FirstName), MiddleName: e(d.MiddleName),
				LastName: e(d.LastName), DateOfBirth: e(d.DateOfBirth), LicenseNumber: e(d.LicenseNumber),
				IssuingCountry: e(d.IssuingCountry), IssuingState: e(d.IssuingState), IssueDate: e(d.IssueDate),
				ExpirationDate: e(d.ExpirationDate), IssuingAuthority: e(d.IssuingAuthority), LicenseClass: e(d.LicenseClass)}
		}
	case CipherTypePassport:
		if d := v.Passport; d != nil {
			c.Passport = &PassportData{Surname: e(d.Surname), GivenName: e(d.GivenName), DateOfBirth: e(d.DateOfBirth),
				Sex: e(d.Sex), BirthPlace: e(d.BirthPlace), Nationality: e(d.Nationality),
				IssuingCountry: e(d.IssuingCountry), PassportNumber: e(d.PassportNumber), PassportType: e(d.PassportType),
				NationalIdentificationNumber: e(d.NationalIdentificationNumber), IssuingAuthority: e(d.IssuingAuthority),
				IssueDate: e(d.IssueDate), ExpirationDate: e(d.ExpirationDate)}
		}
	}
	if v.Fields != nil {
		c.Fields = []FieldData{}
		for _, f := range v.Fields {
			c.Fields = append(c.Fields, FieldData{Type: f.Type, Name: e(f.Name), Value: e(f.Value), LinkedID: f.LinkedID})
		}
	}
	if v.PasswordHistory != nil {
		c.PasswordHistory = []PasswordHistoryData{}
		for _, p := range v.PasswordHistory {
			pw := derefStr(p.Password)
			c.PasswordHistory = append(c.PasswordHistory, PasswordHistoryData{Password: e(&pw), LastUsedDate: cliDate(p.LastUsedDate)})
		}
	}
	return err
}

func encryptAttachments(list []AttachmentView, key *crypto.SymmetricKey) ([]AttachmentData, error) {
	if list == nil {
		return nil, nil
	}
	out := []AttachmentData{}
	for _, a := range list {
		fn, err := encStr(a.FileName, key)
		if err != nil {
			return nil, err
		}
		d := AttachmentData{ID: clonePtr(a.ID), URL: clonePtr(a.URL), FileName: fn, Size: FlexString{Val: clonePtr(a.Size)}, SizeName: clonePtr(a.SizeName)}
		if a.Key != nil {
			w, err := wrapKey(a.Key, key)
			if err != nil {
				return nil, err
			}
			d.Key = &w
		}
		out = append(out, d)
	}
	return out, nil
}

// AdjustCipherHistory mirrors CipherService.adjustCipherHistory for an existing item: it carries
// over the password history from the existing (decrypted) item, records a changed login password
// and changed/removed hidden fields, and trims the history to 5 entries (nil when empty).
func AdjustCipherHistory(model, existing *CipherView) {
	if model.ID == "" {
		return
	}
	if existing != nil {
		model.PasswordHistory = append([]PasswordHistoryView{}, existing.PasswordHistory...)
		if model.Type == CipherTypeLogin && existing.Type == CipherTypeLogin && model.Login != nil && existing.Login != nil {
			ep := existing.Login.Password
			if ep != nil && *ep != "" && (model.Login.Password == nil || *ep != *model.Login.Password) {
				now := time.Now().UTC()
				model.Login.PasswordRevisionDate = &now
				pw := *ep
				model.PasswordHistory = append([]PasswordHistoryView{{Password: &pw, LastUsedDate: &now}}, model.PasswordHistory...)
			} else {
				model.Login.PasswordRevisionDate = existing.Login.PasswordRevisionDate
			}
		}
		if len(existing.Fields) > 0 {
			var hidden []FieldView
			for _, f := range model.Fields {
				if f.Type == FieldTypeHidden && !isNullOrEmpty(f.Name) {
					hidden = append(hidden, f)
				}
			}
			for _, ef := range existing.Fields {
				if ef.Type != FieldTypeHidden || isNullOrEmpty(ef.Name) || isNullOrEmpty(ef.Value) {
					continue
				}
				var matched *FieldView
				for i := range hidden {
					if derefStr(hidden[i].Name) == *ef.Name {
						matched = &hidden[i]
						break
					}
				}
				if matched == nil || matched.Value == nil || *matched.Value != *ef.Value {
					now := time.Now().UTC()
					pw := *ef.Name + ": " + *ef.Value
					model.PasswordHistory = append([]PasswordHistoryView{{Password: &pw, LastUsedDate: &now}}, model.PasswordHistory...)
				}
			}
		}
	}
	if model.PasswordHistory != nil && len(model.PasswordHistory) == 0 {
		model.PasswordHistory = nil
	} else if len(model.PasswordHistory) > 5 {
		model.PasswordHistory = model.PasswordHistory[:5]
	}
}

// EncryptFolder encrypts a folder name with the user key and returns the FolderRequest.
func EncryptFolder(v *FolderView, userKey *crypto.SymmetricKey) (*FolderRequest, error) {
	s, err := crypto.EncryptString(v.Name, userKey)
	if err != nil {
		return nil, err
	}
	return &FolderRequest{Name: s}, nil
}

// EncryptCollectionName encrypts a collection name with its organization key.
func EncryptCollectionName(name, orgID string, keys *Keys) (string, error) {
	key, err := keys.OrgKey(orgID)
	if err != nil {
		return "", errors.New("No encryption key for this organization.")
	}
	return crypto.EncryptString(name, key)
}
