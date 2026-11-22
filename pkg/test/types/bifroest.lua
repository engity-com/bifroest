---@meta
-- Editor-only declarations for EmmyLua-compatible plugins and LuaLS.
-- Do not execute or require this file; the Go runner supplies these functions.

---@class BifroestNull

---@class BifroestRequest
---@field requestingName string
---@field transport? 'ssh'|'http'
---@field method? 'password'|'keyboard-interactive'|'oidc'
---@field host? string
---@field slug? string

---@class BifroestAuthentication
---@field outcome 'allow'|'deny'
---@field mode? 'post-authentication'|'mapped-local'|'verified-oidc'
---@field account? string
---@field oidc? table<string, any>

---@class BifroestInput
---@field request BifroestRequest
---@field authentication table<string, BifroestAuthentication>

---@class BifroestResult
---@field scope 'post-authentication/session-target'
---@field decision 'selected'|'deny'
---@field authenticationAssumed boolean
---@field request BifroestRequest
---@field flow? string
---@field stage? 'local-login'
---@field identity? table<string, string>
---@field authentication? table<string, string>
---@field environment? table<string, any>

---@class BifroestTest
---@field input BifroestInput Original, immutable fixture input.
---@field environment table<string, any> Modeled facts, not the selected target.
---@field configuration table<string, any> Allowlisted configuration view.
---@field IsEqual fun(self: BifroestTest, expected: any, actual: any, reason?: string): boolean

---@class BifroestCase
---@field name string
---@field input BifroestInput
---@field verify fun(t: BifroestTest, actual: BifroestResult)

---@class BifroestPlatform
---@field os? string[]
---@field arch? string[]
---@field version? string[]

---@class BifroestSuite
---@field name string
---@field platform? BifroestPlatform
---@field configuration? string YAML content, not a path.
---@field environment table<string, any>
---@field tests BifroestCase[]

---Register one suite. Validated by Bifröst, not by this declaration file.
---@param _declaration BifroestSuite
function suite(_declaration) end

---Create an immutable object view, preserving the supplied record's fields.
---@generic T
---@param value T
---@return T
function object(value)
  return value
end

---Create an immutable ordered list.
---@generic T
---@param value T[]
---@return T[]
function list(value)
  return value
end

---Read a bounded data file below the physical suite directory.
---@param _path string
---@return string
function file_content(_path)
  return ""
end

---Known explicit null, distinct from an omitted Lua nil field.
---@type BifroestNull
null = {}
