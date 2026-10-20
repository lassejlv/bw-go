package vault

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"strings"
	"time"

	"github.com/lassejlv/bw-go/internal/cli"
	"github.com/lassejlv/bw-go/internal/crypto"
)

// Decryption follows the SDK's lenient_decrypt_cipher_view + CipherView.fromSdkCipherView:
// only failure to obtain the cipher key (or to open a blob) fails the whole item; individual
// field failures leave the value undefined.

// ErrPartialPersonal mirrors CryptoError::RestrictedCipherRequiresOrganization.
var ErrPartialPersonal = errors.New("restricted (partial) cipher requires an organization")

func decStr(p *string, key *crypto.SymmetricKey) (*string, error) {
	if p == nil {
		return nil, nil
	}
	s, err := crypto.DecryptString(*p, key)
	if err != nil {
		return nil, err
	}
	return &s, nil
}

// lenient decrypts an optional EncString, returning nil on failure.
func lenient(p *string, key *crypto.SymmetricKey) *string {
	s, err := decStr(p, key)
	if err != nil {
		return nil
	}
	return s
}

func dateVal(d *cli.Date) time.Time {
	if d == nil {
		return time.Time{}
	}
	return d.Time
}

func datePtr(d *cli.Date) *time.Time {
	if d == nil || d.IsZero() {
		return nil
	}
	t := d.Time
	return &t
}

// DecryptCipher decrypts an encrypted cipher. securityVersion >= 2 enforces URI checksums.
func DecryptCipher(c *Cipher, keys *Keys) (*CipherView, error) {
	if c.IsPartial() && c.OrganizationID == nil {
		return nil, ErrPartialPersonal
	}
	cipherKey, err := keys.CipherKey(c)
	if err != nil {
		return nil, err
	}
	v := baseView(c)
	if c.Key != nil {
		v.Key = cipherKey
	}
	v.Attachments = decryptAttachments(c.Attachments, cipherKey)

	if sealed := c.Data.Val; sealed != nil && IsBlobData(sealed) {
		blob, err := decodeBlob(*sealed, cipherKey)
		if err != nil {
			return nil, err
		}
		applyBlob(v, blob)
		ensureTypeView(v)
		return v, nil
	}

	if c.Name != nil {
		if n, err := decStr(c.Name, cipherKey); err == nil {
			v.Name = *n
		}
	}
	v.Notes = lenient(c.Notes, cipherKey)
	if c.Login != nil {
		v.Login = decryptLogin(c.Login, cipherKey)
		if enforceChecksums(c, keys) {
			removeInvalidChecksums(v.Login)
		}
		v.Login.uriChecksums = nil
		// LoginView.fromSdkLoginView drops URIs with a null/empty uri.
		uris := []LoginURIView{}
		for _, u := range v.Login.URIs {
			if u.URI != nil && *u.URI != "" {
				uris = append(uris, u)
			}
		}
		v.Login.URIs = uris
	}
	if c.Card != nil {
		d := c.Card
		v.Card = &CardView{
			CardholderName: lenient(d.CardholderName, cipherKey), Brand: lenient(d.Brand, cipherKey),
			Number: lenient(d.Number, cipherKey), ExpMonth: lenient(d.ExpMonth, cipherKey),
			ExpYear: lenient(d.ExpYear, cipherKey), Code: lenient(d.Code, cipherKey),
		}
	}
	if c.Identity != nil {
		d := c.Identity
		l := func(p *string) *string { return lenient(p, cipherKey) }
		v.Identity = &IdentityView{
			Title: l(d.Title), FirstName: l(d.FirstName), MiddleName: l(d.MiddleName), LastName: l(d.LastName),
			Address1: l(d.Address1), Address2: l(d.Address2), Address3: l(d.Address3), City: l(d.City),
			State: l(d.State), PostalCode: l(d.PostalCode), Country: l(d.Country), Company: l(d.Company),
			Email: l(d.Email), Phone: l(d.Phone), SSN: l(d.SSN), Username: l(d.Username),
			PassportNumber: l(d.PassportNumber), LicenseNumber: l(d.LicenseNumber),
		}
	}
	if c.SecureNote != nil {
		v.SecureNote = &SecureNoteView{Type: c.SecureNote.Type}
	}
	if c.SshKey != nil {
		if s, err := decryptSshKey(c.SshKey, cipherKey); err == nil {
			v.SshKey = s
		}
	}
	if c.BankAccount != nil {
		d := c.BankAccount
		l := func(p *string) *string { return lenient(p, cipherKey) }
		v.BankAccount = &BankAccountView{
			BankName: l(d.BankName), NameOnAccount: l(d.NameOnAccount), AccountType: l(d.AccountType),
			AccountNumber: l(d.AccountNumber), RoutingNumber: l(d.RoutingNumber), BranchNumber: l(d.BranchNumber),
			Pin: l(d.Pin), SwiftCode: l(d.SwiftCode), Iban: l(d.Iban), BankContactPhone: l(d.BankContactPhone),
		}
	}
	if c.DriversLicense != nil {
		d := c.DriversLicense
		l := func(p *string) *string { return lenient(p, cipherKey) }
		v.DriversLicense = &DriversLicenseView{
			FirstName: l(d.FirstName), MiddleName: l(d.MiddleName), LastName: l(d.LastName),
			DateOfBirth: l(d.DateOfBirth), LicenseNumber: l(d.LicenseNumber), IssuingCountry: l(d.IssuingCountry),
			IssuingState: l(d.IssuingState), IssueDate: l(d.IssueDate), ExpirationDate: l(d.ExpirationDate),
			IssuingAuthority: l(d.IssuingAuthority), LicenseClass: l(d.LicenseClass),
		}
	}
	if c.Passport != nil {
		d := c.Passport
		l := func(p *string) *string { return lenient(p, cipherKey) }
		v.Passport = &PassportView{
			Surname: l(d.Surname), GivenName: l(d.GivenName), DateOfBirth: l(d.DateOfBirth), Sex: l(d.Sex),
			BirthPlace: l(d.BirthPlace), Nationality: l(d.Nationality), IssuingCountry: l(d.IssuingCountry),
			PassportNumber: l(d.PassportNumber), PassportType: l(d.PassportType),
			NationalIdentificationNumber: l(d.NationalIdentificationNumber), IssuingAuthority: l(d.IssuingAuthority),
			IssueDate: l(d.IssueDate), ExpirationDate: l(d.ExpirationDate),
		}
	}
	v.Fields = []FieldView{}
	for _, f := range c.Fields {
		v.Fields = append(v.Fields, FieldView{
			Name: lenient(f.Name, cipherKey), Value: lenient(f.Value, cipherKey), Type: f.Type, LinkedID: f.LinkedID,
		})
	}
	v.PasswordHistory = []PasswordHistoryView{}
	for _, p := range c.PasswordHistory {
		pw := lenient(p.Password, cipherKey)
		if pw == nil {
			pw = strPtr("")
		}
		v.PasswordHistory = append(v.PasswordHistory, PasswordHistoryView{Password: pw, LastUsedDate: datePtr(p.LastUsedDate)})
	}
	ensureTypeView(v)
	return v, nil
}

// baseView copies the unencrypted metadata (CipherView constructor / fromSdkCipherView).
func baseView(c *Cipher) *CipherView {
	v := NewCipherView()
	v.ID = c.ID
	v.OrganizationID = clonePtr(c.OrganizationID)
	v.FolderID = clonePtr(c.FolderID)
	v.Type = c.Type
	v.Favorite = c.Favorite
	v.OrganizationUseTotp = c.OrganizationUseTotp
	v.Edit = c.Edit
	v.ViewPassword = c.CanViewPassword()
	if c.Permissions != nil {
		p := *c.Permissions
		v.Permissions = &p
	} else {
		v.Permissions = nil
	}
	v.CollectionIDs = append([]string{}, c.CollectionIDs...)
	v.RevisionDate = dateVal(c.RevisionDate)
	v.CreationDate = dateVal(c.CreationDate)
	v.DeletedDate = datePtr(c.DeletedDate)
	v.ArchivedDate = datePtr(c.ArchivedDate)
	v.Reprompt = c.Reprompt
	v.Partial = c.IsPartial()
	v.Name = ""
	return v
}

// ensureTypeView guarantees the type-specific view exists (`obj.x ? fromSdk(obj.x) : new XView()`).
func ensureTypeView(v *CipherView) {
	switch v.Type {
	case CipherTypeLogin:
		if v.Login == nil {
			v.Login = &LoginView{}
		}
		if v.Login.URIs == nil {
			v.Login.URIs = []LoginURIView{}
		}
		if v.Login.Fido2Credentials == nil {
			v.Login.Fido2Credentials = []Fido2CredentialView{}
		}
	case CipherTypeCard:
		if v.Card == nil {
			v.Card = &CardView{}
		}
	case CipherTypeIdentity:
		if v.Identity == nil {
			v.Identity = &IdentityView{}
		}
	case CipherTypeSecureNote:
		if v.SecureNote == nil {
			v.SecureNote = &SecureNoteView{}
		}
	case CipherTypeSshKey:
		if v.SshKey == nil {
			v.SshKey = &SshKeyView{}
		}
	case CipherTypeBankAccount:
		if v.BankAccount == nil {
			v.BankAccount = &BankAccountView{}
		}
	case CipherTypeDriversLicense:
		if v.DriversLicense == nil {
			v.DriversLicense = &DriversLicenseView{}
		}
	case CipherTypePassport:
		if v.Passport == nil {
			v.Passport = &PassportView{}
		}
	}
}

// enforceChecksums mirrors remove_invalid_checksums, applied when the cipher has a key or the
// account security version is >= 2.
func enforceChecksums(c *Cipher, keys *Keys) bool {
	return c.Key != nil || (keys != nil && keys.SecurityVersion >= 2)
}

func decryptLogin(d *LoginData, key *crypto.SymmetricKey) *LoginView {
	l := &LoginView{
		Username:             lenient(d.Username, key),
		Password:             lenient(d.Password, key),
		PasswordRevisionDate: datePtr(d.PasswordRevisionDate),
		Totp:                 lenient(d.Totp, key),
		AutofillOnPageLoad:   d.AutofillOnPageLoad,
		URIs:                 []LoginURIView{},
		Fido2Credentials:     []Fido2CredentialView{},
	}
	// URIs: any failing entry drops the whole list (Vec decrypt + .ok()).
	type uriWithSum struct {
		view     LoginURIView
		checksum *string
	}
	var uris []uriWithSum
	ok := true
	for _, u := range d.URIs {
		uri, err := decStr(u.URI, key)
		if err != nil {
			ok = false
			break
		}
		sum, err := decStr(u.URIChecksum, key)
		if err != nil {
			ok = false
			break
		}
		uris = append(uris, uriWithSum{LoginURIView{URI: uri, Match: u.Match}, sum})
	}
	if ok {
		for _, u := range uris {
			l.URIs = append(l.URIs, u.view)
		}
		l.uriChecksums = make([]*string, len(uris))
		for i, u := range uris {
			l.uriChecksums[i] = u.checksum
		}
	}
	if d.Fido2Credentials != nil {
		var creds []Fido2CredentialView
		ok := true
		for _, f := range d.Fido2Credentials {
			cv, err := decryptFido2(&f, key)
			if err != nil {
				ok = false
				break
			}
			creds = append(creds, *cv)
		}
		if ok {
			l.Fido2Credentials = append(l.Fido2Credentials, creds...)
		}
	}
	return l
}

// removeInvalidChecksums drops URIs whose checksum is missing or does not match.
func removeInvalidChecksums(l *LoginView) {
	if l == nil || l.uriChecksums == nil {
		return
	}
	var keep []LoginURIView
	for i, u := range l.URIs {
		if i < len(l.uriChecksums) && checksumValid(u.URI, l.uriChecksums[i]) {
			keep = append(keep, u)
		}
	}
	if keep == nil {
		keep = []LoginURIView{}
	}
	l.URIs = keep
}

func checksumValid(uri, checksum *string) bool {
	if uri == nil || checksum == nil {
		return false
	}
	cs, err := base64.StdEncoding.DecodeString(*checksum)
	if err != nil {
		return false
	}
	h := sha256.Sum256([]byte(*uri))
	return bytes.Equal(h[:], cs)
}

func decryptFido2(f *Fido2CredentialData, key *crypto.SymmetricKey) (*Fido2CredentialView, error) {
	req := func(p *string) (string, error) {
		if p == nil {
			return "", errors.New("missing field")
		}
		return crypto.DecryptString(*p, key)
	}
	var err error
	v := &Fido2CredentialView{CreationDate: datePtr(f.CreationDate)}
	if v.CredentialID, err = req(f.CredentialID); err != nil {
		return nil, err
	}
	if v.KeyType, err = req(f.KeyType); err != nil {
		return nil, err
	}
	if v.KeyAlgorithm, err = req(f.KeyAlgorithm); err != nil {
		return nil, err
	}
	if v.KeyCurve, err = req(f.KeyCurve); err != nil {
		return nil, err
	}
	if v.KeyValue, err = req(f.KeyValue); err != nil {
		return nil, err
	}
	if v.RpID, err = req(f.RpID); err != nil {
		return nil, err
	}
	if v.Counter, err = req(f.Counter); err != nil {
		return nil, err
	}
	disc, err := req(f.Discoverable)
	if err != nil {
		return nil, err
	}
	v.Discoverable = strings.ToLower(disc) == "true"
	if v.UserHandle, err = decStr(f.UserHandle, key); err != nil {
		return nil, err
	}
	if v.UserName, err = decStr(f.UserName, key); err != nil {
		return nil, err
	}
	if v.RpName, err = decStr(f.RpName, key); err != nil {
		return nil, err
	}
	if v.UserDisplayName, err = decStr(f.UserDisplayName, key); err != nil {
		return nil, err
	}
	return v, nil
}

func decryptSshKey(d *SshKeyData, key *crypto.SymmetricKey) (*SshKeyView, error) {
	if d.PrivateKey == nil {
		return nil, errors.New("missing private key")
	}
	priv, err := crypto.DecryptString(*d.PrivateKey, key)
	if err != nil {
		return nil, err
	}
	v := &SshKeyView{PrivateKey: priv}
	if d.PublicKey != nil && d.KeyFingerprint != nil {
		if v.PublicKey, err = crypto.DecryptString(*d.PublicKey, key); err != nil {
			return nil, err
		}
		if v.KeyFingerprint, err = crypto.DecryptString(*d.KeyFingerprint, key); err != nil {
			return nil, err
		}
		return v, nil
	}
	v.PublicKey, v.KeyFingerprint = deriveSSHPublicKeyAndFingerprint(priv)
	return v, nil
}

// decryptAttachments mirrors decrypt_attachments_with_failures; failures are appended after the
// successes with HasDecryptionError set (CipherView.fromSdkCipherView).
func decryptAttachments(list []AttachmentData, key *crypto.SymmetricKey) []AttachmentView {
	out := []AttachmentView{}
	var failed []AttachmentView
	for _, a := range list {
		v := AttachmentView{ID: clonePtr(a.ID), URL: clonePtr(a.URL), Size: clonePtr(a.Size.Val), SizeName: clonePtr(a.SizeName)}
		name, err := decStr(a.FileName, key)
		var akey *crypto.SymmetricKey
		if err == nil && a.Key != nil {
			akey, err = crypto.DecryptToKey(*a.Key, key)
		}
		if err != nil {
			if a.Key != nil {
				if k, kerr := crypto.DecryptToKey(*a.Key, key); kerr == nil {
					v.Key = k
				}
			}
			v.HasDecryptionError = true
			failed = append(failed, v)
			continue
		}
		v.FileName = name
		v.Key = akey
		out = append(out, v)
	}
	return append(out, failed...)
}

// failedCipherView mirrors the decryption-failure placeholder (`new CipherView(cipher)` with
// name "[error: cannot decrypt]").
func failedCipherView(c *Cipher) *CipherView {
	v := baseView(c)
	v.Name = DecryptError
	v.DecryptionFailure = true
	ensureTypeView(v)
	return v
}

// DecryptFolder decrypts a folder with the user key.
func DecryptFolder(f *Folder, userKey *crypto.SymmetricKey) (*FolderView, error) {
	if f.Name == nil {
		return nil, errors.New("folder name missing")
	}
	name, err := crypto.DecryptString(*f.Name, userKey)
	if err != nil {
		return nil, err
	}
	return &FolderView{ID: f.ID, Name: name, RevisionDate: dateVal(f.RevisionDate)}, nil
}

// DecryptCollection decrypts a collection with its organization key. Failures yield a view
// named "[error: cannot decrypt]" with DecryptionFailure set (CollectionView.fromFailedDecryption).
func DecryptCollection(c *Collection, keys *Keys) *CollectionView {
	v := &CollectionView{
		ID: c.ID, OrganizationID: c.OrganizationID, ExternalID: clonePtr(c.ExternalID),
		ReadOnly: c.ReadOnly, HidePasswords: c.HidePasswords, Manage: c.Manage, Assigned: true,
		Type: c.Type, DefaultUserCollectionEmail: clonePtr(c.DefaultUserCollectionEmail),
		HasEnabledAccessRule: c.HasEnabledAccessRule,
	}
	key, err := keys.OrgKey(c.OrganizationID)
	if err == nil && c.Name != nil {
		var name string
		if name, err = crypto.DecryptString(*c.Name, key); err == nil {
			v.Name = name
			return v
		}
	}
	v.Name = DecryptError
	v.DecryptionFailure = true
	return v
}
