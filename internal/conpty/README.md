# Microsoft ConPTY interface library

The DLLs are unmodified subsets of the MIT-licensed NuGet package `Microsoft.Windows.Console.ConPTY`, pinned in `package.go`. Refresh them with `go generate ./internal/conpty`; the generator verifies the package SHA-256 and each DLL's digest and PE machine before writing anything.

Only Windows binaries embed these DLLs. Each relay extracts its process-architecture DLL into a fresh protected directory, verifies it and holds non-writable/non-deletable file handles through library unload. Loading uses an absolute path with only the protected directory and System32 in the DLL search path. No runtime network access or external DLL override is used.

`OpenConsole.exe` is deliberately not shipped: its GUI imports are unsuitable for Nano Server. Microsoft's DLL explicitly supports selecting the inbox `System32/conhost.exe` when OpenConsole is absent (upstream `src/winconpty/winconpty.cpp`, `_ConsoleHostPath`). Its public `ConptyReleasePseudoConsole` allows that host to exit naturally after client disconnect, delivering its final frame and pipe EOF before `ConptyClosePseudoConsole`. This avoids the older signal-thread shutdown race without interpreting opaque HPCON memory or guessing a flush delay.

The package archive digest identifies the source NuGet package, not a DLL or a source-equivalent rebuild. Release notices and SBOMs inventory the shipped DLL subset separately.
