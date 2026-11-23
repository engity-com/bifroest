package test

import (
	"context"
	"fmt"
	"io"
	"reflect"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/arnodel/golua/lib/base"
	rt "github.com/arnodel/golua/runtime"
	"github.com/engity-com/bifroest/pkg/errors"
)

func validName(name string) bool {
	if name == "" || !utf8.ValidString(name) || utf8.RuneCountInString(name) > 80 {
		return false
	}
	for _, r := range name {
		if !unicode.IsPrint(r) || unicode.In(r, unicode.Other_Default_Ignorable_Code_Point, unicode.Variation_Selector) {
			return false
		}
		if !unicode.IsLetter(r) && !unicode.IsNumber(r) && !unicode.IsMark(r) && !strings.ContainsRune(".,-_[]()%@!~=+", r) {
			return false
		}
	}
	return true
}

type dataView struct {
	value   any
	methods map[string]rt.Value
}
type missingValue struct{}
type testSpec struct {
	name   string
	input  any
	verify rt.Callable
}
type suiteSpec struct {
	name          string
	platform      platformSpec
	configuration *string
	environment   any
	tests         []testSpec
}
type luaState struct {
	r               *rt.Runtime
	meta            *rt.Table
	spec            *suiteSpec
	registrationErr error
	assertionErr    error
	result          *Result
	testValue       rt.Value
	fileContent     func(string) (string, error)
	fileErr         error
}

func newLuaState() *luaState {
	r := rt.New(io.Discard)
	base.Load(r)
	// Build a positive allowlist from the base library, then replace _ENV. No
	// package loader, raw access, metatables, I/O, OS, debug, math/random or Go bridge.
	env := rt.NewTable()
	for _, name := range []string{"assert", "error", "type", "tostring", "tonumber", "pairs", "ipairs", "next", "select"} {
		r.SetEnv(env, name, r.GlobalEnv().Get(rt.StringValue(name)))
	}
	s := &luaState{r: r, meta: rt.NewTable()}
	s.add(s.meta, "__index", 2, false, s.index)
	s.add(s.meta, "__tostring", 1, false, func(t *rt.Thread, c *rt.GoCont) (rt.Cont, error) {
		return c.PushingNext1(t.Runtime, rt.StringValue("<controlled-value>")), nil
	})
	s.add(s.meta, "__newindex", 3, false, func(_ *rt.Thread, _ *rt.GoCont) (rt.Cont, error) { return nil, invalid("data views are read-only") })
	s.add(s.meta, "__len", 1, false, func(t *rt.Thread, c *rt.GoCont) (rt.Cont, error) {
		view, err := viewOf(c.Arg(0))
		if err != nil {
			return nil, err
		}
		switch value := view.value.(type) {
		case []any:
			return c.PushingNext1(t.Runtime, rt.IntValue(int64(len(value)))), nil
		default:
			return nil, invalid("length requires a list")
		}
	})
	s.add(env, "object", 1, false, func(t *rt.Thread, c *rt.GoCont) (rt.Cont, error) {
		table, err := c.TableArg(0)
		if err != nil {
			return nil, err
		}
		value, err := s.readTable(table, false, 0, new(int), map[*rt.Table]bool{})
		if err != nil {
			return nil, err
		}
		return c.PushingNext1(t.Runtime, s.wrap(value)), nil
	})
	s.add(env, "list", 1, false, func(t *rt.Thread, c *rt.GoCont) (rt.Cont, error) {
		table, err := c.TableArg(0)
		if err != nil {
			return nil, err
		}
		value, err := s.readTable(table, true, 0, new(int), map[*rt.Table]bool{})
		if err != nil {
			return nil, err
		}
		return c.PushingNext1(t.Runtime, s.wrap(value)), nil
	})
	s.add(env, "suite", 1, false, s.register)
	s.add(env, "file_content", 1, true, func(t *rt.Thread, c *rt.GoCont) (next rt.Cont, err error) {
		defer func() {
			if err != nil {
				s.fileErr = err
			}
		}()
		name, ok := c.Arg(0).TryString()
		if !ok || len(c.Etc()) != 0 || s.fileContent == nil {
			return nil, invalid("file_content requires one string path and a suite directory")
		}
		// The bounded source reader does I/O intentionally. Charge the maximum
		// permitted input before the host operation, not after allocating it.
		t.RequireCPU(maxSource)
		t.RequireMem(maxSource)
		content, err := s.fileContent(name)
		if err != nil {
			return nil, err
		}
		return c.PushingNext1(t.Runtime, rt.StringValue(content)), nil
	})
	s.add(env, "pcall", 1, true, protectedCall)
	r.SetEnv(env, "null", s.wrap(nil))
	// The compiled chunk receives this environment, not the library's global table.
	r.SetRegistry(rt.StringValue("policytest.env"), rt.TableValue(env))
	return s
}

// Unlike GoLua v0.4.1 base.pcall, do not create a child resource context here.
// An ordinary Lua error is catchable; exhaustion of the test's shared budget
// must propagate to the outer CallContext and cannot be turned into success.
func protectedCall(t *rt.Thread, c *rt.GoCont) (rt.Cont, error) {
	if err := c.Check1Arg(); err != nil {
		return nil, err
	}
	t.RequireCPU(1)
	t.RequireMem(128)
	result := rt.NewTerminationWith(c, 0, true)
	err := rt.Call(t, c.Arg(0), c.Etc(), result)
	next := c.Next()
	if err != nil {
		t.Push1(next, rt.BoolValue(false))
		t.Push1(next, rt.ErrorValue(err))
	} else {
		t.Push1(next, rt.BoolValue(true))
		t.Push(next, result.Etc()...)
	}
	return next, nil
}

func (s *luaState) add(table *rt.Table, name string, n int, etc bool, f rt.GoFunctionFunc) rt.Value {
	function := s.r.SetEnvGoFunc(table, name, f, n, etc)
	function.SolemnlyDeclareCompliance(rt.ComplyCpuSafe | rt.ComplyMemSafe | rt.ComplyIoSafe | rt.ComplyTimeSafe)
	return rt.FunctionValue(function)
}

func viewOf(value rt.Value) (*dataView, error) {
	data, ok := value.TryUserData()
	if !ok {
		return nil, invalid("expected a controlled data view")
	}
	view, ok := data.Value().(*dataView)
	if !ok {
		return nil, invalid("unknown userdata is unavailable")
	}
	return view, nil
}

func (s *luaState) wrap(value any) rt.Value {
	s.r.RequireCPU(1)
	s.r.RequireMem(64)
	switch v := value.(type) {
	case string:
		s.r.RequireBytes(len(v))
		return rt.StringValue(v)
	case bool:
		return rt.BoolValue(v)
	case int64:
		return rt.IntValue(v)
	case float64:
		return rt.FloatValue(v)
	default:
		return s.r.NewUserDataValue(&dataView{value: value}, s.meta)
	}
}

func (s *luaState) index(t *rt.Thread, c *rt.GoCont) (rt.Cont, error) {
	view, err := viewOf(c.Arg(0))
	if err != nil {
		return nil, err
	}
	t.RequireCPU(1)
	if key, ok := c.Arg(1).TryString(); ok {
		if method, present := view.methods[key]; present {
			return c.PushingNext1(t.Runtime, method), nil
		}
		if object, ok := view.value.(map[string]any); ok {
			value, present := object[key]
			if !present {
				return nil, invalid("data field was not supplied")
			}
			return c.PushingNext1(t.Runtime, s.wrap(value)), nil
		}
	}
	if key, ok := c.Arg(1).TryInt(); ok {
		if list, ok := view.value.([]any); ok {
			if key < 1 || key > int64(len(list)) {
				return c.PushingNext1(t.Runtime, rt.NilValue), nil
			}
			return c.PushingNext1(t.Runtime, s.wrap(list[key-1])), nil
		}
	}
	return nil, invalid("invalid data view index")
}

func (s *luaState) plain(value rt.Value, depth int, nodes *int, seen map[*rt.Table]bool) (any, error) {
	*nodes++
	s.r.RequireCPU(1)
	s.r.RequireMem(64)
	if *nodes > maxNodes || depth > maxDepth {
		return nil, invalid("data structure limit exceeded")
	}
	if value.IsNil() {
		return missingValue{}, nil
	}
	switch v := value.Interface().(type) {
	case string:
		if len(v) > maxString {
			return nil, invalid("data string limit exceeded")
		}
		s.r.RequireBytes(len(v))
		return v, nil
	case bool, int64, float64:
		return v, nil
	}
	if _, ok := value.TryUserData(); ok {
		view, err := viewOf(value)
		if err != nil {
			return nil, err
		}
		if view.methods != nil {
			return nil, invalid("test context is not a fixture value")
		}
		return s.copyPlain(view.value, depth+1, nodes)
	}
	if table, ok := value.TryTable(); ok {
		return s.readTable(table, false, depth+1, nodes, seen)
	}
	return nil, invalid("unsupported fixture value")
}

// Recount nested views too: repeated object{ previous = priorView } must not
// bypass depth/node limits or create exponentially expanding fixture DAGs.
func (s *luaState) copyPlain(value any, depth int, nodes *int) (any, error) {
	*nodes++
	s.r.RequireCPU(1)
	s.r.RequireMem(64)
	if depth > maxDepth || *nodes > maxNodes {
		return nil, invalid("data structure limit exceeded")
	}
	switch v := value.(type) {
	case map[string]any:
		result := map[string]any{}
		for key, item := range v {
			copyOfItem, err := s.copyPlain(item, depth+1, nodes)
			if err != nil {
				return nil, err
			}
			s.r.RequireBytes(len(key))
			result[key] = copyOfItem
		}
		return result, nil
	case []any:
		s.r.RequireMem(uint64(len(v)) * 32)
		result := make([]any, 0, len(v))
		for _, item := range v {
			copyOfItem, err := s.copyPlain(item, depth+1, nodes)
			if err != nil {
				return nil, err
			}
			result = append(result, copyOfItem)
		}
		return result, nil
	case string:
		s.r.RequireBytes(len(v))
		return v, nil
	default:
		return value, nil
	}
}

func (s *luaState) readTable(table *rt.Table, list bool, depth int, nodes *int, seen map[*rt.Table]bool) (any, error) {
	if depth > maxDepth || seen[table] || table.Metatable() != nil {
		return nil, invalid("cyclic, deep or metatable-backed fixture")
	}
	seen[table] = true
	defer delete(seen, table)
	object := map[string]any{}
	array := []any{}
	if list {
		length := table.Len()
		if length > maxNodes {
			return nil, invalid("list size limit exceeded")
		}
		s.r.RequireMem(uint64(length) * 32)
		array = make([]any, int(length))
	}
	count := 0
	for key := rt.NilValue; ; {
		next, value, ok := table.Next(key)
		if !ok || next.IsNil() {
			break
		}
		key = next
		count++
		if count > maxNodes {
			return nil, invalid("data structure limit exceeded")
		}
		plain, err := s.plain(value, depth+1, nodes, seen)
		if err != nil {
			return nil, err
		}
		if list {
			index, ok := key.TryInt()
			if !ok || index < 1 || index > int64(len(array)) {
				return nil, invalid("lists must have dense integer keys")
			}
			array[index-1] = plain
		} else {
			name, ok := key.TryString()
			if !ok || len(name) > 128 {
				return nil, invalid("objects require bounded string keys; use list for arrays")
			}
			s.r.RequireBytes(len(name))
			object[name] = plain
		}
	}
	if list {
		if count != len(array) {
			return nil, invalid("lists cannot contain holes")
		}
		return array, nil
	}
	return object, nil
}

func (s *luaState) checkKeys(table *rt.Table, allowed ...string) error {
	count := 0
	for key := rt.NilValue; ; {
		next, _, ok := table.Next(key)
		if !ok || next.IsNil() {
			return nil
		}
		key = next
		count++
		s.r.RequireCPU(1)
		if count > maxNodes {
			return invalid("schema size limit exceeded")
		}
		name, ok := key.TryString()
		if !ok {
			return invalid("schema keys must be strings")
		}
		found := false
		for _, candidate := range allowed {
			found = found || name == candidate
		}
		if !found {
			return invalid("unknown suite or test field")
		}
	}
}
func tableField(table *rt.Table, name string) rt.Value { return table.Get(rt.StringValue(name)) }
func stringField(table *rt.Table, name string) (string, error) {
	value, ok := tableField(table, name).TryString()
	if !ok || value == "" || len(value) > maxString {
		return "", invalid("required string field is missing or too large")
	}
	return value, nil
}

func (s *luaState) register(t *rt.Thread, c *rt.GoCont) (next rt.Cont, err error) {
	defer func() {
		if err != nil {
			s.registrationErr = err
		}
	}()
	if s.spec != nil {
		return nil, invalid("exactly one suite is allowed")
	}
	table, err := c.TableArg(0)
	if err != nil {
		return nil, err
	}
	if err := s.checkKeys(table, "name", "platform", "configuration", "environment", "tests"); err != nil {
		return nil, err
	}
	name, err := stringField(table, "name")
	if err != nil || !validName(name) {
		return nil, invalid("invalid suite name")
	}
	platform, err := s.readPlatform(tableField(table, "platform"))
	if err != nil {
		return nil, err
	}
	var configuration *string
	if value := tableField(table, "configuration"); !value.IsNil() {
		plain, ok := value.TryString()
		if !ok || len(plain) > maxSource {
			return nil, invalid("configuration must be a bounded YAML string")
		}
		configuration = &plain
	}
	world, err := s.plain(tableField(table, "environment"), 0, new(int), map[*rt.Table]bool{})
	if err != nil {
		return nil, err
	}
	if _, ok := world.(map[string]any); !ok {
		return nil, invalid("environment must be an object")
	}
	tests, ok := tableField(table, "tests").TryTable()
	if !ok {
		return nil, invalid("tests must be a dense array")
	}
	length := tests.Len()
	if length < 1 || length > maxTests {
		return nil, invalid("suite requires 1 to 64 tests")
	}
	// Validate array keys, not only Lua's ambiguous length for sparse tables.
	count := 0
	for key := rt.NilValue; ; {
		next, _, ok := tests.Next(key)
		if !ok || next.IsNil() {
			break
		}
		key = next
		count++
		t.RequireCPU(1)
		if count > maxTests {
			return nil, invalid("test count limit exceeded")
		}
		index, ok := key.TryInt()
		if !ok || index < 1 || index > length {
			return nil, invalid("tests must be a dense array")
		}
	}
	if int64(count) != length {
		return nil, invalid("tests cannot contain holes")
	}
	spec := &suiteSpec{name: name, platform: platform, configuration: configuration, environment: world}
	names := map[string]bool{}
	for i := int64(1); i <= length; i++ {
		t.RequireCPU(1)
		t.RequireMem(128)
		test, ok := tests.Get(rt.IntValue(i)).TryTable()
		if !ok {
			return nil, invalid("test must be a table")
		}
		if err := s.checkKeys(test, "name", "input", "verify"); err != nil {
			return nil, err
		}
		name, err := stringField(test, "name")
		if err != nil || !validName(name) || names[name] {
			return nil, invalid("invalid or duplicate test name")
		}
		names[name] = true
		input, err := s.plain(tableField(test, "input"), 0, new(int), map[*rt.Table]bool{})
		if err != nil {
			return nil, err
		}
		if _, ok := input.(map[string]any); !ok {
			return nil, invalid("input must be an object")
		}
		verify, ok := tableField(test, "verify").TryClosure()
		if !ok {
			return nil, invalid("verify must be a Lua closure")
		}
		spec.tests = append(spec.tests, testSpec{name: name, input: input, verify: verify})
	}
	s.spec = spec
	return c.Next(), nil
}

func (s *luaState) assertEqual(t *rt.Thread, c *rt.GoCont) (next rt.Cont, err error) {
	defer func() {
		if err != nil {
			s.assertionErr = err
		}
	}()
	if c.NArgs() < 3 || len(c.Etc()) > 0 || !c.Arg(0).Equals(s.testValue) {
		return nil, invalid("IsEqual requires t:IsEqual(expected, actual, reason?)")
	}
	if s.result.Assertions >= maxAssertions {
		return nil, invalid("assertion count limit exceeded")
	}
	s.result.Assertions++
	expected, err := s.plain(c.Arg(1), 0, new(int), map[*rt.Table]bool{})
	if err != nil {
		return nil, err
	}
	actual, err := s.plain(c.Arg(2), 0, new(int), map[*rt.Table]bool{})
	if err != nil {
		return nil, err
	}
	reason := ""
	if !c.Arg(3).IsNil() {
		var ok bool
		reason, ok = c.Arg(3).TryString()
		if !ok || len(reason) > 256 {
			return nil, invalid("assertion reason must be a string of at most 256 bytes")
		}
	}
	t.RequireCPU(maxNodes)
	matched := reflect.DeepEqual(expected, actual)
	if !matched {
		line := int32(0)
		for parent, depth := c.Parent(), 0; parent != nil && depth < maxDepth; parent, depth = parent.Parent(), depth+1 {
			if info := parent.DebugInfo(); info != nil && info.CurrentLine > 0 {
				line = info.CurrentLine
				break
			}
		}
		t.RequireMem(1024)
		s.result.Failures = append(s.result.Failures, Failure{Line: line, Reason: reason, Expected: preview(expected), Actual: preview(actual)})
	}
	return c.PushingNext1(t.Runtime, rt.BoolValue(matched)), nil
}

func preview(value any) string {
	switch v := value.(type) {
	case string:
		if len(v) > 128 {
			v = v[:128] + "…"
		}
		return fmt.Sprintf("%q", v)
	case []any:
		return fmt.Sprintf("<list length=%d>", len(v))
	case map[string]any:
		return "<object>"
	case missingValue:
		return "<absent>"
	case nil:
		return "null"
	default:
		return fmt.Sprintf("%v", v)
	}
}

func (s *luaState) run(ctx context.Context, source []byte, execute func() error) error {
	if !rt.QuotasAvailable {
		return errors.System.Newf("Lua quota support is required")
	}
	if len(source) > maxSource {
		return invalid("suite source limit exceeded")
	}
	if ctx == nil {
		return errors.System.Newf("evaluation context is required")
	}
	if err := ctx.Err(); err != nil {
		return errors.System.Newf("%w", err)
	}
	_, err := s.r.MainThread().CallContext(rt.RuntimeContextDef{
		HardLimits:    rt.RuntimeResources{Cpu: 2_000_000, Memory: 16 << 20, Millis: 500},
		RequiredFlags: rt.ComplyCpuSafe | rt.ComplyMemSafe | rt.ComplyIoSafe | rt.ComplyTimeSafe,
	}, func() error {
		chunk, err := s.r.CompileAndLoadLuaChunk("suite.lua", source, s.r.Registry(rt.StringValue("policytest.env")))
		if err != nil {
			return invalid("cannot compile Lua suite")
		}
		if _, err := rt.Call1(s.r.MainThread(), rt.FunctionValue(chunk)); err != nil {
			return err
		}
		if s.registrationErr != nil {
			return s.registrationErr
		}
		if s.fileErr != nil {
			return s.fileErr
		}
		if execute != nil {
			return execute()
		}
		return nil
	})
	if canceled := ctx.Err(); canceled != nil {
		return errors.System.Newf("%w", canceled)
	}
	if s.registrationErr != nil {
		return s.registrationErr
	}
	if s.assertionErr != nil {
		return s.assertionErr
	}
	if s.fileErr != nil {
		return s.fileErr
	}
	if _, ok := err.(rt.ContextTerminationError); ok {
		return errors.System.Newf("Lua resource quota exceeded")
	}
	if _, ok := err.(*rt.Error); ok {
		return invalid("Lua execution failed")
	}
	return err
}
