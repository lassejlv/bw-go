// Package sendcore is the Send domain: server models, the send key scheme, encryption and
// decryption of Sends, the Send API calls (including file upload and anonymous access) and helpers
// for Send links. It mirrors libs/common/src/tools/send and the parts of the Rust SDK's
// bitwarden-send crate that the CLI needs.
package sendcore

import (
	"encoding/json"
	"time"

	"github.com/lassejlv/bw-go/internal/crypto"
)

// SendType mirrors libs/common/src/tools/send/types/send-type.ts.
const (
	TypeText = 0
	TypeFile = 1
	TypeItem = 2
)

// AuthType mirrors libs/common/src/tools/send/types/auth-type.ts.
const (
	AuthEmail    = 0
	AuthPassword = 1
	AuthNone     = 2
)

// FileUploadType mirrors libs/common/src/platform/enums/file-upload-type.enum.ts.
const (
	FileUploadDirect = 0
	FileUploadAzure  = 1
)

// SendEncryptionV1 is the only SendEncryptionType of Item Send data (SDK SendEncryptionType::V1).
const SendEncryptionV1 = 1

// KdfIterations is SEND_KDF_ITERATIONS: PBKDF2-SHA256 iterations for Send password hashes.
const KdfIterations = 100000

// Key derivation parameters for the send key (SendService.sendKeySalt / sendKeyPurpose).
const (
	KeySalt    = "bitwarden-send"
	KeyPurpose = "send"
	// SeedLength is the length of the random send key seed (createKeyWithPurpose(128, ...)).
	SeedLength = 16
)

// DecryptError is the placeholder for fields that fail to decrypt (EncString.decrypt).
const DecryptError = "[error: cannot decrypt]"

// ---------- server / state models (SendData, SendResponse) ----------

// FileData is SendFileApi / SendFileData. Size is kept as raw JSON because the server sends it
// as a string and the CLI echoes whatever it received.
type FileData struct {
	ID       *string         `json:"id"`
	FileName *string         `json:"fileName"`
	Size     json.RawMessage `json:"size"`
	SizeName *string         `json:"sizeName"`
}

// TextData is SendTextApi / SendTextData.
type TextData struct {
	Text   *string `json:"text"`
	Hidden bool    `json:"hidden"`
}

// ItemMetadata is SendItemMetadataApi.
type ItemMetadata struct {
	ItemID *string `json:"itemId"`
}

// ItemData is SendItemApi: the data of an Item Send. Data is the opaque sealed cipher blob
// (JSON {format_version, wrapped_cek, envelope}) produced by the SDK's
// CipherView::seal_blob_for_item_sends with the send key.
type ItemData struct {
	EncryptionVersion *int          `json:"encryptionVersion"`
	Data              *string       `json:"data"`
	Metadata          *ItemMetadata `json:"metadata"`
}

// Data is a Send as returned by the server (SendResponse) and stored in state (SendData).
// Decoding is case-insensitive so PascalCase and camelCase server JSON both work.
type Data struct {
	ID             string    `json:"id"`
	AccessID       string    `json:"accessId"`
	Type           int       `json:"type"`
	Name           *string   `json:"name"`
	Notes          *string   `json:"notes"`
	File           *FileData `json:"file"`
	Text           *TextData `json:"text"`
	Data           *ItemData `json:"data"`
	Key            *string   `json:"key"`
	MaxAccessCount *int      `json:"maxAccessCount"`
	AccessCount    int       `json:"accessCount"`
	RevisionDate   *string   `json:"revisionDate"`
	ExpirationDate *string   `json:"expirationDate"`
	DeletionDate   *string   `json:"deletionDate"`
	Password       *string   `json:"password"`
	Emails         *string   `json:"emails"`
	Disabled       bool      `json:"disabled"`
	HideEmail      bool      `json:"hideEmail"`
	AuthType       *int      `json:"authType"`
}

// AccessData is the server's SendAccessResponse (POST /sends/access).
type AccessData struct {
	ID                string    `json:"id"`
	Type              int       `json:"type"`
	Name              *string   `json:"name"`
	File              *FileData `json:"file"`
	Text              *TextData `json:"text"`
	Data              *ItemData `json:"data"`
	ExpirationDate    *string   `json:"expirationDate"`
	CreatorIdentifier *string   `json:"creatorIdentifier"`
}

// FileUploadData is SendFileUploadDataResponse (POST /sends/file/v2, GET /sends/{id}/file/{fileId}).
type FileUploadData struct {
	FileUploadType int             `json:"fileUploadType"`
	SendResponse   json.RawMessage `json:"sendResponse"`
	URL            string          `json:"url"`
}

// FileDownloadData is SendFileDownloadDataResponse.
type FileDownloadData struct {
	ID  string `json:"id"`
	URL string `json:"url"`
}

// ---------- request model (SendRequest) ----------

// TextAPI is the text part of a request.
type TextAPI struct {
	Text   *string `json:"text"`
	Hidden bool    `json:"hidden"`
}

// FileAPI is the file part of a request (only the encrypted file name is sent).
type FileAPI struct {
	FileName *string `json:"fileName"`
}

// Request is SendRequest. Fields that are `undefined` in the TypeScript model are omitted.
type Request struct {
	Type           int       `json:"type"`
	FileLength     *int      `json:"fileLength,omitempty"`
	Name           *string   `json:"name"`
	Notes          *string   `json:"notes"`
	MaxAccessCount *int      `json:"maxAccessCount"`
	ExpirationDate *string   `json:"expirationDate"`
	DeletionDate   *string   `json:"deletionDate"`
	Key            *string   `json:"key"`
	Password       *string   `json:"password,omitempty"`
	Emails         *string   `json:"emails"`
	Disabled       *bool     `json:"disabled,omitempty"`
	HideEmail      *bool     `json:"hideEmail,omitempty"`
	AuthType       *int      `json:"authType,omitempty"`
	Text           *TextAPI  `json:"text,omitempty"`
	File           *FileAPI  `json:"file,omitempty"`
	Data           *ItemData `json:"data,omitempty"`
}

// ---------- decrypted views ----------

// TextView is SendTextView.
type TextView struct {
	Text   *string
	Hidden bool
}

// FileView is SendFileView.
type FileView struct {
	ID       *string
	Size     json.RawMessage
	SizeName *string
	FileName *string
}

// View is a decrypted Send (SendView).
type View struct {
	ID       string
	AccessID string
	Name     *string
	Notes    *string
	// Key is the 16 byte seed the send key is derived from (the part after the id in the link).
	Key []byte
	// CryptoKey is the derived 64 byte send key.
	CryptoKey *crypto.SymmetricKey
	Type      int
	Text      *TextView
	File      *FileView
	// Item is the decrypted cipher of an Item Send (see OpenItemData).
	Item           json.RawMessage
	MaxAccessCount *int
	AccessCount    int
	RevisionDate   *time.Time
	DeletionDate   *time.Time
	ExpirationDate *time.Time
	// Password is the stored password hash (non-nil means the Send is password protected).
	Password  *string
	Emails    []string
	Disabled  *bool
	HideEmail *bool
	AuthType  *int
}

// URLB64Key returns the seed as unpadded url-safe base64, as used in Send links.
func (v *View) URLB64Key() string { return ToURLB64(v.Key) }

// AccessView is a decrypted SendAccessResponse (SendAccessView).
type AccessView struct {
	ID                string
	Name              *string
	Type              int
	Text              *TextView
	File              *FileView
	Item              json.RawMessage
	ExpirationDate    *time.Time
	CreatorIdentifier *string
}
