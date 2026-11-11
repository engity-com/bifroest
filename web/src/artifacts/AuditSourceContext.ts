import { createContext } from 'react';
import type { AuditlogSummary, WebAccess } from '../remember';

// One selected public configuration hint, never a permission or evidence result.
// Source/actor checks remain mandatory before reusing it for a collection.
export const AuditSourceContext = createContext<{
  access: WebAccess;
  source: AuditlogSummary | null;
  select(source: AuditlogSummary): void;
} | null>(null);
