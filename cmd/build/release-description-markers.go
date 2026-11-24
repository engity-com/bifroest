package main

import (
	"fmt"
	"regexp"
	"strings"
)

const (
	releaseArtifactsBegin       = "<!-- BEGIN: RELEASE ARTIFACTS -->"
	releaseArtifactsEnd         = "<!-- END: RELEASE ARTIFACTS -->"
	releaseArtifactsPlaceholder = "<!-- RELEASE ARTIFACTS -->"
)

var (
	releaseArtifactsBeginPattern       = regexp.MustCompile("(?i)" + regexp.QuoteMeta(releaseArtifactsBegin))
	releaseArtifactsEndPattern         = regexp.MustCompile("(?i)" + regexp.QuoteMeta(releaseArtifactsEnd))
	releaseArtifactsPlaceholderPattern = regexp.MustCompile("(?i)" + regexp.QuoteMeta(releaseArtifactsPlaceholder))
)

func replaceReleaseArtifacts(body, fragment string) (string, error) {
	begin := releaseArtifactsBeginPattern.FindAllStringIndex(body, -1)
	end := releaseArtifactsEndPattern.FindAllStringIndex(body, -1)
	newline := "\n"
	if strings.Contains(body, "\r\n") {
		newline = "\r\n"
	}
	fragment = strings.ReplaceAll(strings.TrimRight(fragment, "\r\n"), "\r\n", "\n")
	fragment = strings.ReplaceAll(fragment, "\n", newline)
	if len(begin) != 0 || len(end) != 0 {
		if len(begin) != 1 || len(end) != 1 || begin[0][1] > end[0][0] {
			return "", fmt.Errorf("release artifacts require exactly one ordered BEGIN/END marker pair")
		}
		return body[:begin[0][1]] + newline + newline + fragment + newline + newline + body[end[0][0]:], nil
	}
	block := releaseArtifactsBegin + newline + newline + fragment + newline + newline + releaseArtifactsEnd
	placeholder := releaseArtifactsPlaceholderPattern.FindAllStringIndex(body, -1)
	if len(placeholder) > 1 {
		return "", fmt.Errorf("release description has multiple RELEASE ARTIFACTS placeholders")
	}
	if len(placeholder) == 1 {
		return body[:placeholder[0][0]] + block + body[placeholder[0][1]:], nil
	}
	separator := ""
	if body != "" && !strings.HasSuffix(body, newline+newline) {
		separator = newline
		if !strings.HasSuffix(body, newline) {
			separator += newline
		}
	}
	return body + separator + block + newline, nil
}
