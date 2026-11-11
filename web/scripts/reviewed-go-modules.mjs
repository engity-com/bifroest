// A dependency graph must contain exactly one reviewed version of every module
// path. Reviewed alternatives accommodate the branch and its main-merge graph;
// they never permit extra/missing modules or two versions of the same module.
export function completeReviewedInventory(actual, reviewed) {
  const approved = new Set(reviewed);
  const path = (name) => {
    const separator = name.lastIndexOf('@');
    return separator > 0 && separator < name.length - 1 ? name.slice(0, separator) : null;
  };
  const required = new Set([...approved].map(path));
  if (required.has(null)) {
    return false;
  }
  const found = new Set();
  for (const name of actual) {
    const module = path(name);
    if (!approved.has(name) || module === null || found.has(module)) {
      return false;
    }
    found.add(module);
  }
  return found.size === required.size && [...required].every((module) => found.has(module));
}
