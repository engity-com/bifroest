import { useState } from 'react';

// A local component-lifetime key, not a global grant registry. React retries the
// conditional state adjustment before committing children, so an old owner's
// state/DOM cannot be displayed once new owner props have been committed.
export function useOwnerKey(owner: object): number {
    const [binding, setBinding] = useState({ owner, key: 0 });
    if (binding.owner !== owner) {
        setBinding({ owner, key: binding.key + 1 });
    }
    return binding.key;
}
