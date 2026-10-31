// Package webui serves public browser resources, never authentication or commands.
package webui

import (
	"bytes"
	"crypto/rand"
	"embed"
	"encoding/base64"
	"errors"
	"io"
	"io/fs"
	"mime"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"unicode/utf8"

	"golang.org/x/net/html"
	"golang.org/x/net/html/atom"

	"github.com/engity-com/bifroest/pkg/configuration"
)

const Prefix = "/_bifroest/files/"
const KeyWorkerPath = Prefix + "browser-key-worker.js"
const TransferWorkerPath = Prefix + "browser-transfer-worker.js"
const EvidenceWorkerPath = Prefix + "browser-evidence-worker.js"
const CustomPrefix = "/_bifroest/custom/"
const maxFile = 8 << 20
const maxIndex = 512 << 10

var ErrAsset = errors.New("public browser asset unavailable or unsafe")

// The tracked README keeps source-only Go/SSH builds possible. Release frontend
// preparation adds generated resources before Go embeds them; Node is build-only.
//
//go:embed all:assets
var bundled embed.FS

type Assets struct {
	embedded   fs.FS
	overlay    *os.Root
	custom     []*os.Root
	css, js    []string
	head, body string
}

func New(conf *configuration.Http) (*Assets, error) {
	base, err := fs.Sub(bundled, "assets")
	if err != nil {
		return nil, ErrAsset
	}
	result := &Assets{embedded: base}
	fail := func() (*Assets, error) { _ = result.Close(); return nil, ErrAsset }
	if conf == nil {
		return result, nil
	}
	if len(conf.CustomCss) > 64 || len(conf.CustomJs) > 64 || len(conf.CustomHtmlHead) > maxIndex || len(conf.CustomHtmlBody) > maxIndex {
		return fail()
	}
	result.head, result.body = conf.CustomHtmlHead, conf.CustomHtmlBody
	if conf.AssetsDirectory != "" {
		result.overlay, err = openPublicRoot(conf.AssetsDirectory)
		if err != nil {
			return fail()
		}
	}
	for _, list := range []struct {
		files       []string
		destination *[]string
	}{{conf.CustomCss, &result.css}, {conf.CustomJs, &result.js}} {
		for _, file := range list.files {
			root, err := openPublicRoot(filepath.Dir(file))
			if err != nil {
				return fail()
			}
			name := filepath.Base(file)
			if _, err := readPublic(root, name, maxFile); err != nil {
				_ = root.Close()
				return fail()
			}
			result.custom = append(result.custom, root)
			*list.destination = append(*list.destination, name)
		}
	}
	// A missing unbuilt index is allowed for API-only source development, but an
	// existing malformed/unsafe overlay must never silently fall through to embed.
	if raw, err := result.Read("index.html"); err == nil {
		if _, _, err := result.render(raw); err != nil {
			return fail()
		}
	} else if !errors.Is(err, fs.ErrNotExist) {
		return fail()
	}
	return result, nil
}

func (this *Assets) Close() error {
	var result error
	if this.overlay != nil {
		result = errors.Join(result, this.overlay.Close())
	}
	for _, root := range this.custom {
		result = errors.Join(result, root.Close())
	}
	return result
}

func safeResource(name string) bool {
	if len(name) == 0 || len(name) > 1024 || !fs.ValidPath(name) {
		return false
	}
	for _, part := range strings.Split(name, "/") {
		if part == "" || part[0] == '.' || strings.HasSuffix(part, ".") || len(part) > 200 {
			return false
		}
		for _, c := range part {
			allowed := c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '-' || c == '.'
			if !allowed {
				return false
			}
		}
		base := strings.ToUpper(strings.SplitN(part, ".", 2)[0])
		if base == "CON" || base == "PRN" || base == "AUX" || base == "NUL" || len(base) == 4 && (strings.HasPrefix(base, "COM") || strings.HasPrefix(base, "LPT")) && base[3] >= '1' && base[3] <= '9' {
			return false
		}
	}
	return true
}

func openPublicRoot(directory string) (*os.Root, error) {
	before, err := os.Lstat(directory)
	if err != nil || !before.IsDir() || before.Mode()&os.ModeSymlink != 0 {
		return nil, ErrAsset
	}
	root, err := os.OpenRoot(directory)
	if err != nil {
		return nil, ErrAsset
	}
	current, err := root.Stat(".")
	if err != nil || !os.SameFile(before, current) {
		_ = root.Close()
		return nil, ErrAsset
	}
	return root, nil
}

func noSymlinks(root *os.Root, name string) error {
	var current string
	for _, part := range strings.Split(filepath.ToSlash(name), "/") {
		current = path.Join(current, part)
		info, err := root.Lstat(current)
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return ErrAsset
		}
	}
	return nil
}

func readPublic(root *os.Root, name string, limit int64) ([]byte, error) {
	if err := noSymlinks(root, name); err != nil {
		return nil, err
	}
	before, err := root.Lstat(name)
	if err != nil {
		return nil, err
	}
	if !before.Mode().IsRegular() || before.Size() > limit {
		return nil, ErrAsset
	}
	file, err := root.Open(name)
	if err != nil {
		return nil, ErrAsset
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(before, opened) || !singleLink(file, opened) {
		return nil, ErrAsset
	}
	data, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil || int64(len(data)) > limit {
		return nil, ErrAsset
	}
	after, err := file.Stat()
	if err != nil {
		return nil, ErrAsset
	}
	current, err := root.Lstat(name)
	if err != nil || !os.SameFile(after, current) || !os.SameFile(opened, after) || !singleLink(file, after) || opened.Size() != after.Size() || !opened.ModTime().Equal(after.ModTime()) || int64(len(data)) != after.Size() || noSymlinks(root, name) != nil {
		return nil, ErrAsset
	}
	return data, nil
}

func (this *Assets) Read(name string) ([]byte, error) {
	if !safeResource(name) {
		return nil, ErrAsset
	}
	limit := int64(maxFile)
	if name == "index.html" {
		limit = maxIndex
	}
	if this.overlay != nil {
		data, err := readPublic(this.overlay, name, limit)
		if !errors.Is(err, fs.ErrNotExist) {
			return data, err
		}
	}
	file, err := this.embedded.Open(name)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > limit {
		return nil, ErrAsset
	}
	return io.ReadAll(io.LimitReader(file, limit+1))
}

func (this *Assets) Available() bool { _, err := this.Read("index.html"); return err == nil }

func (this *Assets) Resource(urlPath string) ([]byte, string, error) {
	var data []byte
	var err error
	var extension string
	if strings.HasPrefix(urlPath, Prefix) {
		name := strings.TrimPrefix(urlPath, Prefix)
		if name == "index.html" {
			return nil, "", fs.ErrNotExist
		}
		data, err = this.Read(name)
		extension = path.Ext(name)
	} else if strings.HasPrefix(urlPath, CustomPrefix) {
		parts := strings.Split(strings.TrimPrefix(urlPath, CustomPrefix), "/")
		if len(parts) != 2 {
			return nil, "", fs.ErrNotExist
		}
		var names []string
		var offset int
		switch parts[0] {
		case "css":
			names = this.css
			extension = ".css"
		case "js":
			names = this.js
			offset = len(this.css)
			extension = ".js"
		default:
			return nil, "", fs.ErrNotExist
		}
		id, parseErr := strconv.Atoi(strings.TrimSuffix(parts[1], extension))
		if parseErr != nil || id < 0 || id >= len(names) || parts[1] != strconv.Itoa(id)+extension {
			return nil, "", fs.ErrNotExist
		}
		data, err = readPublic(this.custom[offset+id], names[id], maxFile)
	} else {
		return nil, "", fs.ErrNotExist
	}
	contentType := mime.TypeByExtension(extension)
	if contentType == "" {
		contentType = "application/octet-stream"
	}
	return data, contentType, err
}

func (this *Assets) Document() ([]byte, string, error) {
	raw, err := this.Read("index.html")
	if err != nil {
		return nil, "", err
	}
	return this.render(raw)
}

func (this *Assets) render(raw []byte) ([]byte, string, error) {
	if len(raw) > maxIndex || !utf8.Valid(raw) {
		return nil, "", ErrAsset
	}
	document, err := html.Parse(bytes.NewReader(raw))
	if err != nil {
		return nil, "", ErrAsset
	}
	var head, body *html.Node
	for node := document.FirstChild; node != nil; node = node.NextSibling {
		if node.Type != html.ElementNode || node.Data != "html" {
			continue
		}
		for child := node.FirstChild; child != nil; child = child.NextSibling {
			if child.Type == html.ElementNode && child.Data == "head" {
				head = child
			}
			if child.Type == html.ElementNode && child.Data == "body" {
				body = child
			}
		}
	}
	if head == nil || body == nil {
		return nil, "", ErrAsset
	}
	appendHTML := func(parent *html.Node, text string) error {
		nodes, err := html.ParseFragment(strings.NewReader(text), parent)
		if err != nil {
			return ErrAsset
		}
		for _, node := range nodes {
			parent.AppendChild(node)
		}
		return nil
	}
	for id := range this.css {
		node := &html.Node{Type: html.ElementNode, Data: "link", DataAtom: atom.Link, Attr: []html.Attribute{{Key: "rel", Val: "stylesheet"}, {Key: "href", Val: CustomPrefix + "css/" + strconv.Itoa(id) + ".css"}}}
		head.AppendChild(node)
	}
	if appendHTML(head, this.head) != nil {
		return nil, "", ErrAsset
	}
	for id := range this.js {
		node := &html.Node{Type: html.ElementNode, Data: "script", DataAtom: atom.Script, Attr: []html.Attribute{{Key: "defer"}, {Key: "src", Val: CustomPrefix + "js/" + strconv.Itoa(id) + ".js"}}}
		body.AppendChild(node)
	}
	if appendHTML(body, this.body) != nil {
		return nil, "", ErrAsset
	}
	var random [32]byte
	if _, err := rand.Read(random[:]); err != nil {
		return nil, "", ErrAsset
	}
	nonce := base64.StdEncoding.EncodeToString(random[:])
	var secure func(*html.Node)
	secure = func(node *html.Node) {
		var external bool
		for _, attr := range node.Attr {
			if attr.Key == "src" || node.Namespace == "svg" && attr.Key == "href" {
				external = true
			}
		}
		if node.Type == html.ElementNode && (node.Data == "style" || node.Data == "script") {
			attrs := node.Attr[:0]
			for _, attr := range node.Attr {
				if attr.Key != "nonce" {
					attrs = append(attrs, attr)
				}
			}
			node.Attr = attrs
			if node.Data == "style" || !external {
				node.Attr = append(node.Attr, html.Attribute{Key: "nonce", Val: nonce})
			}
		}
		for child := node.FirstChild; child != nil; {
			next := child.NextSibling
			remove := false
			if child.Type == html.ElementNode && child.Data == "meta" {
				for _, attr := range child.Attr {
					if attr.Key == "name" && strings.EqualFold(attr.Val, "bifroest-nonce") {
						remove = true
					}
				}
			}
			if remove {
				node.RemoveChild(child)
			} else {
				secure(child)
			}
			child = next
		}
	}
	secure(document)
	head.AppendChild(&html.Node{Type: html.ElementNode, Data: "meta", DataAtom: atom.Meta, Attr: []html.Attribute{{Key: "name", Val: "bifroest-nonce"}, {Key: "content", Val: nonce}}})
	var result bytes.Buffer
	if html.Render(&result, document) != nil || result.Len() > 2*maxIndex {
		return nil, "", ErrAsset
	}
	return result.Bytes(), nonce, nil
}
