export const managementPermissions = [
    'version.read',
    'metrics.read',
    'flows.read',
    'flows.credentials',
    'sessions.read',
    'sessions.disconnect',
    'sessions.dispose',
    'auditlogs.read',
    'auditlogs.events',
    'auditlogs.verify',
    'auditlogs.download',
    'recordings.read',
    'recordings.verify',
    'recordings.download',
    'keys.read',
] as const;
export type ManagementPermission = (typeof managementPermissions)[number];
export const noManagementPermissions: readonly ManagementPermission[] = Object.freeze([]);

export function managementCapabilities(value: unknown): readonly ManagementPermission[] {
    if (
        !Array.isArray(value) ||
        value.length > managementPermissions.length ||
        new Set(value).size !== value.length ||
        value.some((entry) => !managementPermissions.includes(entry))
    ) {
        throw new Error('invalid management capabilities');
    }
    return Object.freeze([...value]) as readonly ManagementPermission[];
}
