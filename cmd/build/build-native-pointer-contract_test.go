package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"testing"

	"github.com/stretchr/testify/require"
)

// Go's syscall annotation must extend to our outer uintptr wrappers. Keeping
// only the uintptr slice alive does not keep an out-parameter's original stack
// address stable while lazy DLL resolution grows the caller's goroutine stack.
func TestNativeSAMWrappersPreservePointerArgumentsAcrossStackGrowth(t *testing.T) {
	for _, test := range []struct{ path, name string }{
		{"../../pkg/windowslocal/account_windows.go", "netCall"},
		{"../../pkg/environment/local-account-management_windows.go", "localSAMCall"},
	} {
		t.Run(test.name, func(t *testing.T) {
			file, err := parser.ParseFile(token.NewFileSet(), test.path, nil, parser.ParseComments)
			require.NoError(t, err)
			found := false
			for _, declaration := range file.Decls {
				function, ok := declaration.(*ast.FuncDecl)
				if !ok || function.Name.Name != test.name {
					continue
				}
				found = true
				annotated := false
				if function.Doc != nil {
					for _, comment := range function.Doc.List {
						if comment.Text == "//go:uintptrescapes" {
							annotated = true
						}
					}
				}
				require.True(t, annotated, "the outer native wrapper must preserve pointer liveness and stable addresses, not only the uintptr slice")
			}
			require.True(t, found, "native wrapper was not found")
		})
	}
}
