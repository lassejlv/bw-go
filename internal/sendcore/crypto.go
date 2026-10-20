package sendcore

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/lassejlv/bw-go/internal/cli"
	"github.com/lassejlv/bw-go/internal/crypto"
)

// ErrItemSendUnsupported is returned for Item Sends until data envelopes are available.
var ErrItemSendUnsupported = errors.New("Item type Sends require the SDK to decrypt")

// NewSeed returns a fresh random send key seed (SendService.encrypt -> createKeyWithPurpose(128)).
func NewSeed() []byte { return crypto.RandomBytes(SeedLength) }

// MakeSendKey derives the 64 byte send key from the seed with HKDF-SHA256
// (salt "bitwarden-send", info "send"), like LegacyCompatKeyService.makeSendKey and the SDK's
// derive_shareable_key.
func MakeSendKey(seed []byte) (*crypto.SymmetricKey, error) {
	if len(seed) == 0 {
		return nil, errors.New("Send key is missing.")
	}
	return crypto.NewSymmetricKey(crypto.HKDF(seed, KeySalt, KeyPurpose, 64))
}

// HashPassword derives the base64 password hash used to protect and access a Send:
// PBKDF2-SHA256(password, salt = seed, 100000 iterations, 32 bytes).
func HashPassword(password string, seed []byte) string {
	return base64.StdEncoding.EncodeToString(crypto.PBKDF2([]byte(password), seed, KdfIterations, 32))
}

// OpenItemData decrypts the sealed cipher blob of an Item Send with the send key and returns
// the decrypted cipher as JSON.
//
// TODO(v2-crypto): the blob is the SDK's SealedCipherBlob (JSON {format_version, wrapped_cek,
// envelope}): wrapped_cek is an EncString of the content encryption key wrapped by the send key,
// envelope is a COSE data envelope holding the CipherBlobV1 (see bitwarden-vault
// cipher/blob/encryption.rs unseal_blob_for_item_sends). Wire this to
// crypto.OpenDataEnvelopeWithWrappingKey(envelope, wrapped_cek, <cipher blob namespace>, sendKey)
// and convert the CBOR CipherBlobV1 into the vault package's cipher view (restoring the id from
// item.Metadata.ItemID). Upstream's CLI (legacy path) rejects Item Sends with this same error.
func OpenItemData(item *ItemData, sendKey *crypto.SymmetricKey) (json.RawMessage, error) {
	return nil, ErrItemSendUnsupported
}

// SealItemData is the inverse of OpenItemData (CipherView::seal_blob_for_item_sends).
//
// TODO(v2-crypto): implement with crypto.SealDataEnvelope; encryptionVersion is SendEncryptionV1
// and metadata.itemId is the cipher id.
func SealItemData(cipher json.RawMessage, sendKey *crypto.SymmetricKey) (*ItemData, error) {
	return nil, errors.New("Item type Send functionality not yet available")
}

func decryptString(enc *string, key *crypto.SymmetricKey) (*string, error) {
	if enc == nil {
		return nil, nil
	}
	s, err := crypto.DecryptString(*enc, key)
	if err != nil {
		return nil, err
	}
	return &s, nil
}

// decryptLenient mirrors Domain.decryptObj: failures become "[error: cannot decrypt]".
func decryptLenient(enc *string, key *crypto.SymmetricKey) *string {
	s, err := decryptString(enc, key)
	if err != nil {
		e := DecryptError
		return &e
	}
	return s
}

func encryptString(s *string, key *crypto.SymmetricKey) (*string, error) {
	if s == nil {
		return nil, nil
	}
	e, err := crypto.EncryptString(*s, key)
	if err != nil {
		return nil, err
	}
	return &e, nil
}

func parseDate(s *string) *time.Time {
	if s == nil || *s == "" {
		return nil
	}
	t, err := cli.ParseDate(*s)
	if err != nil {
		return nil
	}
	return &t
}

func formatDate(t *time.Time) *string {
	if t == nil {
		return nil
	}
	s := cli.FormatDate(*t)
	return &s
}

func decryptText(t *TextData, key *crypto.SymmetricKey) *TextView {
	if t == nil {
		return nil
	}
	return &TextView{Text: decryptLenient(t.Text, key), Hidden: t.Hidden}
}

func decryptFile(f *FileData, key *crypto.SymmetricKey) *FileView {
	if f == nil {
		return nil
	}
	return &FileView{ID: f.ID, Size: f.Size, SizeName: f.SizeName, FileName: decryptLenient(f.FileName, key)}
}

// UnwrapSeed decrypts the send key seed with the user key.
func UnwrapSeed(encKey string, userKey *crypto.SymmetricKey) ([]byte, error) {
	e, err := crypto.ParseEncString(encKey)
	if err != nil {
		return nil, err
	}
	return e.Decrypt(userKey)
}

// Decrypt decrypts a Send with the user key (Send.decrypt).
func Decrypt(d *Data, userKey *crypto.SymmetricKey) (*View, error) {
	v := &View{
		ID:             d.ID,
		AccessID:       d.AccessID,
		Type:           d.Type,
		MaxAccessCount: d.MaxAccessCount,
		AccessCount:    d.AccessCount,
		RevisionDate:   parseDate(d.RevisionDate),
		DeletionDate:   parseDate(d.DeletionDate),
		ExpirationDate: parseDate(d.ExpirationDate),
		Password:       d.Password,
		Disabled:       &d.Disabled,
		HideEmail:      &d.HideEmail,
		AuthType:       d.AuthType,
		Emails:         []string{},
	}
	if d.Key == nil {
		return nil, errors.New("Send key is missing.")
	}
	seed, err := UnwrapSeed(*d.Key, userKey)
	if err != nil {
		return nil, err
	}
	v.Key = seed
	if v.CryptoKey, err = MakeSendKey(seed); err != nil {
		return nil, err
	}
	if v.Name, err = decryptString(d.Name, v.CryptoKey); err != nil {
		return nil, err
	}
	if v.Notes, err = decryptString(d.Notes, v.CryptoKey); err != nil {
		return nil, err
	}
	if d.Emails != nil && *d.Emails != "" {
		for _, e := range strings.Split(*d.Emails, ",") {
			v.Emails = append(v.Emails, strings.TrimSpace(e))
		}
	}
	switch d.Type {
	case TypeText:
		v.Text = decryptText(d.Text, v.CryptoKey)
	case TypeFile:
		v.File = decryptFile(d.File, v.CryptoKey)
	case TypeItem:
		if v.Item, err = OpenItemData(d.Data, v.CryptoKey); err != nil {
			return nil, err
		}
	}
	return v, nil
}

// DecryptAccess decrypts an anonymous access response with the seed from the Send link
// (SendDecryptionService.decryptSendAccess). It returns the view and the derived send key, which
// also decrypts the file contents of a File Send.
func DecryptAccess(d *AccessData, seed []byte) (*AccessView, *crypto.SymmetricKey, error) {
	key, err := MakeSendKey(seed)
	if err != nil {
		return nil, nil, err
	}
	v := &AccessView{
		ID:                d.ID,
		Type:              d.Type,
		ExpirationDate:    parseDate(d.ExpirationDate),
		CreatorIdentifier: d.CreatorIdentifier,
	}
	switch d.Type {
	case TypeItem:
		if v.Item, err = OpenItemData(d.Data, key); err != nil {
			return nil, nil, err
		}
	}
	v.Name = decryptLenient(d.Name, key)
	switch d.Type {
	case TypeText:
		v.Text = decryptText(d.Text, key)
	case TypeFile:
		v.File = decryptFile(d.File, key)
	}
	return v, key, nil
}

// Encrypt encrypts a view into a request (SendService.encrypt). file is the plaintext file
// content for a new File Send (nil otherwise); the returned bytes are the encrypted file
// (EncArrayBuffer layout) to upload. password is the plaintext password, or nil to leave it
// unset. A view without a seed gets a fresh one (and key) like upstream.
func Encrypt(v *View, file []byte, password *string, userKey *crypto.SymmetricKey) (*Request, []byte, error) {
	if userKey == nil {
		return nil, nil, errors.New("No user key found.")
	}
	if v.Key == nil {
		v.Key = NewSeed()
		k, err := MakeSendKey(v.Key)
		if err != nil {
			return nil, nil, err
		}
		v.CryptoKey = k
	} else if v.CryptoKey == nil {
		k, err := MakeSendKey(v.Key)
		if err != nil {
			return nil, nil, err
		}
		v.CryptoKey = k
	}
	req := &Request{
		Type:           v.Type,
		MaxAccessCount: v.MaxAccessCount,
		ExpirationDate: formatDate(v.ExpirationDate),
		DeletionDate:   formatDate(v.DeletionDate),
		Disabled:       v.Disabled,
		HideEmail:      v.HideEmail,
		AuthType:       v.AuthType,
	}
	if len(v.Emails) > 0 {
		trimmed := make([]string, len(v.Emails))
		for i, e := range v.Emails {
			trimmed[i] = strings.TrimSpace(e)
		}
		s := strings.ToLower(strings.Join(trimmed, ","))
		req.Emails = &s
	} else if password != nil {
		// Not used for encryption: a proof that the client knows the password and the seed.
		h := HashPassword(*password, v.Key)
		req.Password = &h
	}

	encKey, err := crypto.Encrypt(v.Key, userKey)
	if err != nil {
		return nil, nil, err
	}
	ks := encKey.String()
	req.Key = &ks
	if req.Name, err = encryptString(v.Name, v.CryptoKey); err != nil {
		return nil, nil, err
	}
	if req.Notes, err = encryptString(v.Notes, v.CryptoKey); err != nil {
		return nil, nil, err
	}

	var encFile []byte
	switch v.Type {
	case TypeText:
		if v.Text == nil {
			return nil, nil, errors.New("Cannot read properties of null (reading 'text')")
		}
		t := &TextAPI{Hidden: v.Text.Hidden}
		if t.Text, err = encryptString(v.Text.Text, v.CryptoKey); err != nil {
			return nil, nil, err
		}
		req.Text = t
	case TypeFile:
		f := &FileAPI{}
		var name *string
		if v.File != nil && v.File.FileName != nil {
			name = v.File.FileName
		}
		if file != nil {
			if name == nil {
				empty := ""
				name = &empty
			}
			if f.FileName, err = encryptString(name, v.CryptoKey); err != nil {
				return nil, nil, err
			}
			if encFile, err = crypto.EncryptBytes(file, v.CryptoKey); err != nil {
				return nil, nil, err
			}
			n := len(encFile)
			req.FileLength = &n
		} else if name != nil && *name != "" {
			if f.FileName, err = encryptString(name, v.CryptoKey); err != nil {
				return nil, nil, err
			}
		}
		req.File = f
	case TypeItem:
		if req.Data, err = SealItemData(v.Item, v.CryptoKey); err != nil {
			return nil, nil, err
		}
	}
	return req, encFile, nil
}
