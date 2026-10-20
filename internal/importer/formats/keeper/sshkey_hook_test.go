package keeper

// Links the real SSH key import (internal/sshkey assigns importer.ImportSSHKey from init()) into
// this test binary, so the SSH key tests run instead of skipping.
import _ "github.com/lassejlv/bw-go/internal/sshkey"
