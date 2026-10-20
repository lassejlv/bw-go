package importer

import (
	"errors"
	"fmt"
	"reflect"
	"testing"

	"github.com/lassejlv/bw-go/internal/importer/model"
)

// Ported from libs/importer/src/services/import.service.spec.ts ("setImportTarget") plus the
// importImportResult checks.

func targetFolder() *model.FolderView {
	return &model.FolderView{ID: "myImportTarget", Name: "myImportTarget"}
}

func targetCollection(t model.CollectionType) *model.CollectionView {
	return &model.CollectionView{ID: "myImportTarget", Name: "myImportTarget", OrganizationID: "org", Type: t}
}

func TestSetImportTarget(t *testing.T) {
	folder1 := func() *model.FolderView { return &model.FolderView{ID: "folder1", Name: "folder1"} }
	folder2 := func() *model.FolderView { return &model.FolderView{ID: "folder2", Name: "folder2"} }
	col1 := func() *model.CollectionView {
		return &model.CollectionView{ID: "collection1", Name: "collection1", OrganizationID: "org"}
	}
	col2 := func() *model.CollectionView {
		return &model.CollectionView{ID: "collection2", Name: "collection2", OrganizationID: "org"}
	}

	t.Run("empty importTarget does nothing", func(t *testing.T) {
		r := model.NewImportResult()
		if err := SetImportTarget(r, "", nil); err != nil || len(r.Folders) != 0 || r.TargetFolderIncluded {
			t.Fatal(err)
		}
	})

	t.Run("passing importTarget adds it to folders", func(t *testing.T) {
		r := model.NewImportResult()
		tf := targetFolder()
		if err := SetImportTarget(r, "", &ImportTarget{Folder: tf}); err != nil {
			t.Fatal(err)
		}
		if len(r.Folders) != 1 || r.Folders[0] != tf || !r.TargetFolderIncluded {
			t.Fatalf("%+v", r)
		}
	})

	t.Run("sets it as new root for all existing folders", func(t *testing.T) {
		r := model.NewImportResult()
		r.Folders = []*model.FolderView{folder1(), folder2()}
		tf := targetFolder()
		SetImportTarget(r, "", &ImportTarget{Folder: tf})
		if !reflect.DeepEqual(folderNames(r), []string{"myImportTarget", "myImportTarget/folder1", "myImportTarget/folder2"}) || r.Folders[0] != tf {
			t.Fatalf("%v", folderNames(r))
		}
	})

	t.Run("adds it to collections", func(t *testing.T) {
		r := model.NewImportResult()
		tc := targetCollection(model.CollectionTypeShared)
		SetImportTarget(r, "org", &ImportTarget{Collection: tc})
		if len(r.Collections) != 1 || r.Collections[0] != tc || !r.TargetCollectionIncluded {
			t.Fatalf("%+v", r)
		}
	})

	t.Run("sets it as new root for all existing collections", func(t *testing.T) {
		r := model.NewImportResult()
		r.Collections = []*model.CollectionView{col1(), col2()}
		tc := targetCollection(model.CollectionTypeShared)
		SetImportTarget(r, "org", &ImportTarget{Collection: tc})
		if len(r.Collections) != 3 || r.Collections[0] != tc ||
			r.Collections[1].Name != "myImportTarget/collection1" || r.Collections[2].Name != "myImportTarget/collection2" {
			t.Fatalf("%+v", r.Collections)
		}
	})

	t.Run("wrong target kind errors", func(t *testing.T) {
		if err := SetImportTarget(model.NewImportResult(), "org", &ImportTarget{Folder: targetFolder()}); err == nil || err.Error() != MsgErrorAssigningTargetCollection {
			t.Fatal(err)
		}
		if err := SetImportTarget(model.NewImportResult(), "", &ImportTarget{Collection: col1()}); err == nil || err.Error() != MsgErrorAssigningTargetFolder {
			t.Fatal(err)
		}
	})

	t.Run("collectionRelationship has the expected values", func(t *testing.T) {
		r := model.NewImportResult()
		r.Ciphers = ciphersNamed("cipher1", "cipher2")
		r.CollectionRelationships = []model.Relationship{{0, 0}}
		r.Collections = []*model.CollectionView{col1(), col2()}
		SetImportTarget(r, "org", &ImportTarget{Collection: targetCollection(model.CollectionTypeShared)})
		if !reflect.DeepEqual(r.CollectionRelationships, []model.Relationship{{1, 0}, {0, 1}}) {
			t.Fatalf("%v", r.CollectionRelationships)
		}
	})

	t.Run("folderRelationship has the expected values", func(t *testing.T) {
		r := model.NewImportResult()
		r.Folders = []*model.FolderView{folder1(), folder2()}
		r.Ciphers = []*model.CipherView{{Name: "cipher1", FolderID: "folder1"}, {Name: "cipher2"}}
		r.FolderRelationships = []model.Relationship{{0, 0}}
		SetImportTarget(r, "", &ImportTarget{Folder: targetFolder()})
		if !reflect.DeepEqual(r.FolderRelationships, []model.Relationship{{1, 0}, {0, 1}}) {
			t.Fatalf("%v", r.FolderRelationships)
		}
	})

	t.Run("assigns the target to ciphers whose folderId has no relationship", func(t *testing.T) {
		r := model.NewImportResult()
		r.Ciphers = []*model.CipherView{{Name: "cipher1", FolderID: "source-folder-id"}}
		SetImportTarget(r, "", &ImportTarget{Folder: targetFolder()})
		if r.Ciphers[0].FolderID != "myImportTarget" || !reflect.DeepEqual(r.FolderRelationships, []model.Relationship{{0, 0}}) {
			t.Fatalf("%+v", r)
		}
	})

	t.Run("DefaultUserCollection becomes the root for all ciphers", func(t *testing.T) {
		r := model.NewImportResult()
		r.Collections = []*model.CollectionView{col1(), col2()}
		r.Ciphers = ciphersNamed("cipher1", "cipher2", "cipher3")
		r.CollectionRelationships = []model.Relationship{{0, 0}, {1, 1}, {2, 0}}
		tc := targetCollection(model.CollectionTypeDefaultUserCollection)
		SetImportTarget(r, "org", &ImportTarget{Collection: tc})
		if len(r.Collections) != 1 || r.Collections[0] != tc || !r.TargetCollectionIncluded ||
			!reflect.DeepEqual(r.CollectionRelationships, []model.Relationship{{0, 0}, {1, 0}, {2, 0}}) {
			t.Fatalf("%+v", r)
		}
	})

	t.Run("DefaultUserCollection rejects ciphers in multiple collections", func(t *testing.T) {
		r := model.NewImportResult()
		r.Collections = []*model.CollectionView{col1(), col2()}
		r.Ciphers = ciphersNamed("cipher1")
		r.CollectionRelationships = []model.Relationship{{0, 0}, {0, 1}}
		if err := SetImportTarget(r, "org", &ImportTarget{Collection: targetCollection(model.CollectionTypeDefaultUserCollection)}); err == nil {
			t.Fatal("expected error")
		}
	})

	t.Run("DefaultUserCollection preserves folders", func(t *testing.T) {
		r := model.NewImportResult()
		r.Folders = []*model.FolderView{folder1(), folder2()}
		r.Ciphers = []*model.CipherView{{Name: "cipher1", FolderID: "folder1"}, {Name: "cipher2", FolderID: "folder2"}}
		SetImportTarget(r, "org", &ImportTarget{Collection: targetCollection(model.CollectionTypeDefaultUserCollection)})
		if !reflect.DeepEqual(folderNames(r), []string{"folder1", "folder2"}) ||
			!reflect.DeepEqual(r.FolderRelationships, []model.Relationship{{0, 0}, {1, 1}}) ||
			!reflect.DeepEqual(r.CollectionRelationships, []model.Relationship{{0, 0}, {1, 0}}) {
			t.Fatalf("%+v", r)
		}
	})

	t.Run("DefaultUserCollection converts collections to folders", func(t *testing.T) {
		r := model.NewImportResult()
		r.Collections = []*model.CollectionView{col1(), col2()}
		r.Ciphers = []*model.CipherView{{Name: "cipher1", CollectionIDs: []string{"collection1"}}, {Name: "cipher2", CollectionIDs: []string{"collection2"}}}
		SetImportTarget(r, "org", &ImportTarget{Collection: targetCollection(model.CollectionTypeDefaultUserCollection)})
		if len(r.Collections) != 1 || !reflect.DeepEqual(r.CollectionRelationships, []model.Relationship{{0, 0}, {1, 0}}) ||
			!reflect.DeepEqual(folderNames(r), []string{"collection1", "collection2"}) || !r.TargetCollectionIncluded || r.TargetFolderIncluded {
			t.Fatalf("%+v", r)
		}
	})
}

type fakeImporter struct {
	res *model.ImportResult
	err error
}

func (f fakeImporter) Parse(string) (*model.ImportResult, error) { return f.res, f.err }

func login(name, password string) *model.CipherView {
	c := model.NewCipherView()
	c.Name = name
	c.Login.Password = password
	return c
}

func TestImportAndPrepare(t *testing.T) {
	check := func(name string, imp Importer, p ImportParams, want string) {
		t.Helper()
		_, err := Import(imp, "x", p)
		if (err == nil) != (want == "") || (err != nil && err.Error() != want) {
			t.Errorf("%s: got %v, want %q", name, err, want)
		}
	}
	ok := func(ciphers ...*model.CipherView) *model.ImportResult {
		r := model.NewImportResult()
		r.Success = true
		r.Ciphers = ciphers
		return r
	}

	check("syntax error", fakeImporter{err: NewSyntaxError(errors.New("bad"))}, ImportParams{}, MsgImportFormatError)
	check("other error", fakeImporter{err: errors.New("boom")}, ImportParams{}, "boom")
	check("unsuccessful", fakeImporter{res: model.NewImportResult()}, ImportParams{}, MsgImportFormatError)
	failed := model.NewImportResult()
	failed.ErrorMessage = "custom"
	check("unsuccessful with message", fakeImporter{res: failed}, ImportParams{}, "custom")
	check("nothing", fakeImporter{res: ok()}, ImportParams{}, MsgImportNothingError)
	check("bad data", fakeImporter{res: ok(login("--", ""), login("", " "), login("--", ""))}, ImportParams{}, MsgImportFormatError)
	check("good", fakeImporter{res: ok(login("a", "p"))}, ImportParams{}, "")
	check("org unassigned", fakeImporter{res: ok(login("a", "p"))}, ImportParams{OrganizationID: "org"}, MsgImportUnassignedItemsError)
	check("org with permission", fakeImporter{res: ok(login("a", "p"))}, ImportParams{OrganizationID: "org", CanAccessImportExport: true}, "")

	card := model.NewCipherView()
	card.Type = model.CipherTypeCard
	card.Name = "card"
	r, err := Import(fakeImporter{res: ok(login("a", "p"), card)}, "", ImportParams{RestrictedTypes: []model.CipherType{model.CipherTypeCard}})
	if err != nil || len(r.Ciphers) != 1 {
		t.Fatalf("restricted types: %v %+v", err, r)
	}
}

func TestServerError(t *testing.T) {
	r := model.NewImportResult()
	r.Ciphers = []*model.CipherView{login("a", "p"), login("b", "q")}
	r.Folders = []*model.FolderView{{Name: "F"}}
	err := ServerError("ignored", []ValidationError{
		{Key: "Ciphers[1].Name", Messages: []string{"too long", "bad"}},
		{Key: "Folders[0].Name", Messages: []string{"nope"}},
	}, r)
	want := "[2] [Login] \"b\": too long,bad\n\n[Folder] \"F\": nope"
	if err.Error() != want {
		t.Fatalf("%q", err.Error())
	}
	if ServerError("plain", nil, r).Error() != "plain" {
		t.Fatal("plain")
	}
}

func TestSkippedItemsMessage(t *testing.T) {
	got := SkippedItemsMessage([]model.ImportRecordError{
		{ID: "abc", Reason: model.ImportRecordErrorReasonSshKeyParseFailed},
		{ID: " ", Reason: model.ImportRecordErrorReasonError},
	})
	want := "2 item(s) could not be imported and were skipped:\n  - abc: SSH key could not be imported\n  - (unidentified item): could not be imported"
	if got != want || SkippedItemsMessage(nil) != "" {
		t.Fatalf("%q", got)
	}
	if NewGuid() == NewGuid() || len(NewGuid()) != 36 {
		t.Fatal("NewGuid")
	}
}

func TestDropRestrictedTypesReindexes(t *testing.T) {
	r := &model.ImportResult{
		Ciphers: []*model.CipherView{
			{Name: "a", Type: model.CipherTypeLogin},
			{Name: "card", Type: model.CipherTypeCard},
			{Name: "b", Type: model.CipherTypeLogin},
		},
		FolderRelationships:     []model.Relationship{{0, 0}, {1, 1}, {2, 2}},
		CollectionRelationships: []model.Relationship{{2, 5}},
	}
	DropRestrictedTypes(r, []model.CipherType{model.CipherTypeCard})
	if len(r.Ciphers) != 2 || r.Ciphers[1].Name != "b" {
		t.Fatalf("ciphers %+v", r.Ciphers)
	}
	if fmt.Sprint(r.FolderRelationships) != "[[0 0] [1 2]]" || fmt.Sprint(r.CollectionRelationships) != "[[1 5]]" {
		t.Fatalf("rels %v %v", r.FolderRelationships, r.CollectionRelationships)
	}
}
