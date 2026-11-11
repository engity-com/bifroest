// xterm's supported documentOverride keeps its own style creation scoped to this
// instance. No global createElement patch, unsafe-inline or post-insertion nonce.
export function noncedDocument(document: Document, nonce: string): Document {
  if (!/^[A-Za-z0-9+/]{43}=$/.test(nonce)) {
    throw new Error('terminal document policy unavailable');
  }
  const bound = new Map<PropertyKey, unknown>();
  return new Proxy(document, {
    get(target, property) {
      if (property === 'createElement') {
        return (name: string, options?: ElementCreationOptions) => {
          const element = target.createElement(name, options);
          if (name.toLowerCase() === 'style') {
            element.setAttribute('nonce', nonce);
          }
          return element;
        };
      }
      const value = Reflect.get(target, property, target) as unknown;
      if (typeof value !== 'function' || property === 'constructor') {
        return value;
      }
      if (!bound.has(property)) {
        bound.set(property, value.bind(target));
      }
      return bound.get(property);
    },
  });
}
