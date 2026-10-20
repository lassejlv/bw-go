package vault

import (
	"encoding/json"
	"testing"
	"time"
)

func TestTotpSDKVectors(t *testing.T) {
	at := tm("2023-01-01T00:00:00Z")
	cases := map[string]string{
		"WQIQ25BRKZYCJVYP": "194506",
		"wqiq25brkzycjvyp": "194506",
		"PIUDISEQYA":       "829846",
		"PIUDISEQYA======": "829846",
		"PIUD1IS!EQYA=":    "829846",
		"steam://HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ":            "7W6CJ",
		"StEam://HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ":            "7W6CJ",
		"steam://ABCD123":                                     "N26DF",
		"ddfdf":                                               "932653",
		"HJSGFJHDFDJDJKSDFD":                                  "000034",
		"xvdsfasdfasdasdghsgsdfg":                             "403786",
		"KAKFJWOSFJ12NWL":                                     "093430",
		"otpauth://totp/test-account?secret=WQIQ25BRKZYCJVYP": "194506",
		"OTPauth://totp/test-account?secret=WQIQ25BRKZYCJVYP": "194506",
		"otpauth://totp/test-account?secret=WQIQ25BRKZYCJVYP&algorithm=SHA256": "842615",
	}
	for key, want := range cases {
		r, err := GenerateTotp(key, at)
		if err != nil {
			t.Fatal(err)
		}
		if r.Code != want || r.Period != 30 {
			t.Fatalf("%s: got %s/%d want %s", key, r.Code, r.Period, want)
		}
	}
	r, _ := GenerateTotp("otpauth://totp/test-account?secret=WQIQ25BRKZYCJVYP&period=60", at)
	if r.Code != "730364" || r.Period != 60 {
		t.Fatalf("period: %+v", r)
	}
	p, _ := ParseTotp("otpauth://totp/test-issuer:test-account@example.com?secret=WQIQ25BRKZYCJVYP&issuer=other-test-issuer")
	if *p.Issuer != "other-test-issuer" || *p.Account != "test-account@example.com" {
		t.Fatalf("label parse %+v", p)
	}
	if _, err := GenerateTotp("otpauth://totp/x?digits=6", at); err != ErrTotpMissingSecret {
		t.Fatal("missing secret")
	}
}

func TestTotpRFC6238(t *testing.T) {
	// RFC 6238 Appendix B (8 digits). Seeds are ASCII "12345678901234567890" (+ repeats).
	seeds := map[string]string{
		"sha1":   "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ",
		"sha256": "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZA",
		"sha512": "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNA",
	}
	vectors := []struct {
		t    int64
		sha1 string
		s256 string
		s512 string
	}{
		{59, "94287082", "46119246", "90693936"},
		{1111111109, "07081804", "68084774", "25091201"},
		{1111111111, "14050471", "67062674", "99943326"},
		{1234567890, "89005924", "91819424", "93441116"},
		{2000000000, "69279037", "90698825", "38618901"},
		{20000000000, "65353130", "77737706", "47863826"},
	}
	for _, v := range vectors {
		at := time.Unix(v.t, 0)
		for alg, want := range map[string]string{"sha1": v.sha1, "sha256": v.s256, "sha512": v.s512} {
			r, err := GenerateTotp("otpauth://totp/x?secret="+seeds[alg]+"&digits=8&algorithm="+alg, at)
			if err != nil {
				t.Fatal(err)
			}
			if r.Code != want {
				t.Fatalf("t=%d %s: got %s want %s", v.t, alg, r.Code, want)
			}
		}
	}
}

func TestGetDomainHostHostname(t *testing.T) {
	dom := map[string]string{
		"https://www.google.com/path":              "google.com",
		"google.com":                               "google.com",
		"https://user:pw@sub.example.co.uk:8443/x": "example.co.uk",
		"https://foo.bar.github.io":                "bar.github.io",
		"http://localhost:8080":                    "localhost",
		"https://app.localhost":                    "localhost",
		"http://192.168.1.1/admin":                 "192.168.1.1",
		"https://[::1]:8080/":                      "::1",
		"androidapp://com.example.app":             "example.app",
	}
	for in, want := range dom {
		got := GetDomain(in)
		if got == nil || *got != want {
			t.Fatalf("GetDomain(%q) = %v want %s", in, got, want)
		}
	}
	for _, in := range []string{"", "data:text/plain", "about:blank", "intranet", "https://com"} {
		if got := GetDomain(in); got != nil {
			t.Fatalf("GetDomain(%q) = %s, want nil", in, *got)
		}
	}
	if h := GetHost("https://Example.com:443/x"); h == nil || *h != "example.com" {
		t.Fatalf("host %v", h)
	}
	if h := GetHost("example.com:8080/x"); h == nil || *h != "example.com:8080" {
		t.Fatalf("host %v", h)
	}
	if h := GetHost("nodots"); h != nil {
		t.Fatal("host without protocol or dot")
	}
	if h := GetHostname("https://WWW.Example.com/x"); h == nil || *h != "www.example.com" {
		t.Fatalf("hostname %v", h)
	}
}

func TestURIMatching(t *testing.T) {
	m := func(mt UriMatch) *UriMatch { return &mt }
	cases := []struct {
		uri    string
		match  *UriMatch
		target string
		eq     []string
		want   bool
	}{
		{"https://accounts.google.com", nil, "https://mail.google.com/inbox", nil, true},
		{"https://google.com", nil, "https://script.google.com/x", nil, false}, // blacklist
		{"https://example.com", nil, "https://example.org", nil, false},
		{"https://example.com", nil, "https://example.org", []string{"example.com", "example.org"}, true},
		{"https://a.example.com", m(UriMatchHost), "https://a.example.com:443/login", nil, true},
		{"https://a.example.com", m(UriMatchHost), "https://b.example.com", nil, false},
		{"https://a.example.com:8080", m(UriMatchHost), "https://a.example.com", nil, false},
		{"https://example.com/login", m(UriMatchStartsWith), "https://example.com/login?x=1", nil, true},
		{"https://example.com/login", m(UriMatchStartsWith), "https://example.com/", nil, false},
		{"https://example.com/", m(UriMatchExact), "https://example.com/", nil, true},
		{"https://example.com/", m(UriMatchExact), "https://example.com", nil, false},
		{`^https://.*\.EXAMPLE\.com`, m(UriMatchRegularExpression), "https://x.example.com", nil, true},
		{`(?<=x)`, m(UriMatchRegularExpression), "https://x.example.com", nil, false},
		{"https://example.com", m(UriMatchNever), "https://example.com", nil, false},
		{"https://xn--0zwm56d.com", nil, "https://测试.com/x", nil, true},
	}
	for _, c := range cases {
		u := LoginURIView{URI: sp(c.uri), Match: c.match}
		if got := u.MatchesURI(c.target, c.eq, nil, false); got != c.want {
			t.Fatalf("%s vs %s: got %v", c.uri, c.target, got)
		}
	}
	never := LoginURIView{URI: sp("https://example.com"), Match: m(UriMatchNever)}
	if !never.MatchesURI("https://example.com", nil, nil, true) {
		t.Fatal("override never")
	}
	host := UriMatchHost
	def := LoginURIView{URI: sp("https://a.example.com")}
	if def.MatchesURI("https://b.example.com", nil, &host, false) {
		t.Fatal("default match strategy not applied")
	}
	eq := EquivalentDomainsFor("https://www.youtube.com", [][]string{{"google.com", "youtube.com"}, {"apple.com", "icloud.com"}})
	if len(eq) != 2 || eq[0] != "google.com" {
		t.Fatalf("equivalent domains %v", eq)
	}
}

func TestSearchCiphersBasic(t *testing.T) {
	a := NewCipherView()
	a.ID, a.Name = "abcdef12-0000-0000-0000-000000000000", "Email Work MyCompany"
	a.Login = &LoginView{Username: sp("alice@mycompany.com"), URIs: []LoginURIView{{URI: sp("https://portal.corp.example.com/login")}}}
	a.Notes = sp("Archived")
	b := NewCipherView()
	b.ID, b.Name, b.Type = "bbbbbbbb-0000-0000-0000-000000000000", "Café card", CipherTypeCard
	b.Card = &CardView{Brand: sp("Visa"), Number: sp("4111111111111234")}
	list := []*CipherView{a, b}
	cases := map[string]int{
		"email work":     1,
		"alice mycomp":   1,
		"alice archived": 1,
		"work email":     1,
		"mycomp mail":    1,
		"portal.corp":    1,
		"cafe":           1,
		"CAFÉ":           1,
		"*1234":          1,
		"abcdef12":       1,
		"abcdef1":        0,
		"zzz":            0,
		"visa":           1,
	}
	for q, want := range cases {
		if got := len(SearchCiphersBasic(list, q)); got != want {
			t.Fatalf("search %q: got %d want %d", q, got, want)
		}
	}
}

func TestSortCiphers(t *testing.T) {
	mk := func(name, user string) *CipherView {
		v := NewCipherView()
		v.Name = name
		v.Login.Username = sp(user)
		return v
	}
	list := []*CipherView{mk("b", ""), mk("item10", ""), mk("A", "z"), mk("item2", ""), mk("a", "b")}
	SortCiphers(list)
	var got []string
	for _, c := range list {
		got = append(got, c.Name+"/"+*c.Login.Username)
	}
	want := []string{"a/b", "A/z", "b/", "item2/", "item10/"}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("sort: %v", got)
		}
	}
}

func TestRestrictedTypes(t *testing.T) {
	orgs := []*Organization{
		{ProfileOrganization: ProfileOrganization{ID: "o1", Status: OrgUserStatusConfirmed, Type: OrgUserUser, Enabled: true, UsePolicies: true}, IsMember: true},
		{ProfileOrganization: ProfileOrganization{ID: "o2", Status: OrgUserStatusConfirmed, Type: OrgUserOwner, Enabled: true, UsePolicies: true}, IsMember: true},
	}
	policies := []*Policy{{ID: "p1", OrganizationID: "o1", Type: PolicyRestrictedItemTypes, Enabled: true, Data: json.RawMessage(`null`)}}
	r := RestrictedTypes(policies, orgs)
	if len(r) != 1 || r[0].CipherType != CipherTypeCard || len(r[0].AllowViewOrgIDs) != 1 || r[0].AllowViewOrgIDs[0] != "o2" {
		t.Fatalf("restricted %+v", r)
	}
	o1, o2 := "o1", "o2"
	if !IsCipherRestricted(CipherTypeCard, nil, r) || !IsCipherRestricted(CipherTypeCard, &o1, r) ||
		IsCipherRestricted(CipherTypeCard, &o2, r) || IsCipherRestricted(CipherTypeLogin, nil, r) {
		t.Fatal("isCipherRestricted")
	}
	policies[0].Data = json.RawMessage(`[1,3]`)
	r = RestrictedTypes(policies, orgs)
	if len(r) != 2 {
		t.Fatalf("data types %+v", r)
	}
	// Owners are exempt from most policies (default), but not from RestrictedItemTypes.
	owned := []*Policy{{OrganizationID: "o2", Type: PolicyOrganizationDataOwnership, Enabled: true}}
	if PolicyAppliesToUser(owned, orgs, PolicyOrganizationDataOwnership) {
		t.Fatal("owner should be exempt")
	}
	owned[0].Type = PolicyRestrictedItemTypes
	if !PolicyAppliesToUser(owned, orgs, PolicyRestrictedItemTypes) {
		t.Fatal("restricted item types applies to owners")
	}
}
