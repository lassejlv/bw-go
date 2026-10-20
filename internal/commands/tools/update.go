package tools

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"runtime"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/lassejlv/bw-go/internal/app"
	"github.com/lassejlv/bw-go/internal/cli"
	"github.com/lassejlv/bw-go/internal/commands/root"
	"github.com/lassejlv/bw-go/internal/version"
)

// Release endpoints (update.command.ts). This port tracks the upstream CLI's release versions
// (internal/version), so it checks the upstream release list. Override at build time with
// -ldflags "-X github.com/lassejlv/bw-go/internal/commands/tools.ReleasesEndpoint=...".
var (
	ReleasesEndpoint   = "https://api.github.com/repos/bitwarden/clients/releases"
	DefaultDownloadURL = "https://github.com/bitwarden/clients/releases"
)

type githubRelease struct {
	TagName string  `json:"tag_name"`
	Body    *string `json:"body"`
	Assets  []struct {
		BrowserDownloadURL *string `json:"browser_download_url"`
	} `json:"assets"`
}

// Update runs `bw update` (UpdateCommand.run).
func Update(a *app.App) *cli.Response {
	client := http.DefaultClient
	if a != nil && a.API != nil && a.API.HTTP != nil {
		client = a.API.HTTP
	}
	req, err := http.NewRequest("GET", ReleasesEndpoint, nil)
	if err != nil {
		return cli.Error(err)
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "Bitwarden_CLI/"+version.Version+" (Go)")
	c := *client
	if c.Timeout == 0 || c.Timeout > time.Minute {
		c.Timeout = time.Minute
	}
	resp, err := c.Do(req)
	if err != nil {
		return cli.Error(err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return cli.Error(err)
	}
	return updateFromReleases(resp.StatusCode, body, version.Version, runtime.GOOS)
}

func updateFromReleases(status int, body []byte, currentVersion, goos string) *cli.Response {
	if status != 200 {
		return cli.Error(fmt.Sprintf("Error contacting update API: %d", status))
	}
	var releases []githubRelease
	if err := json.Unmarshal(body, &releases); err != nil {
		return cli.Error(err)
	}
	var cliRelease *githubRelease
	for i := range releases {
		if strings.Contains(releases[i].TagName, "cli") {
			cliRelease = &releases[i]
			break
		}
	}
	if cliRelease == nil {
		return cli.Error("Could not find latest CLI version.")
	}
	if cliRelease.TagName == "cli-v"+currentVersion {
		res := cli.NewMessageNull("No update available.")
		res.NoColor = true
		return cli.Success(res)
	}

	downloadURL := getDownloadURL(cliRelease, goos)
	message := ""
	if cliRelease.Body != nil && *cliRelease.Body != "" {
		message = *cliRelease.Body + "\n\n"
	}
	message += "You can download this update at " + downloadURL
	// This port is a standalone binary, like the upstream pkg builds.
	message += "\n\nIf you installed this CLI through a package manager " +
		"you should probably update using its update command instead."
	res := cli.NewMessage("A new version is available: "+cliRelease.TagName, message).SetRaw(downloadURL)
	return cli.Success(res)
}

func getDownloadURL(release *githubRelease, goos string) string {
	marker := map[string]string{"windows": "bw-windows", "darwin": "bw-macos", "linux": "bw-linux"}[goos]
	for _, a := range release.Assets {
		if a.BrowserDownloadURL == nil {
			continue
		}
		d := *a.BrowserDownloadURL
		if !strings.Contains(d, ".zip") {
			continue
		}
		if marker != "" && strings.Contains(d, marker) {
			return d
		}
	}
	return DefaultDownloadURL
}

const updateHelp = "\n  Notes:\n\n" +
	"    Returns the URL to download the newest version of this CLI tool.\n\n" +
	"    Use the `--raw` option to return only the download URL for the update.\n\n" +
	"  Examples:\n\n" +
	"    bwgo update\n" +
	"    bwgo update --raw\n"

func newUpdateCommand(a *app.App) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "update",
		Short: "Check for updates.",
		Run: func(cmd *cobra.Command, args []string) {
			cli.Process(Update(a), false)
		},
	}
	root.Examples(cmd, updateHelp)
	return cmd
}
