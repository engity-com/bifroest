// Management-only US English copy. Transport actions retain their protocol names.
const messages = {
    searchUser: 'Search by requesting user',
    searchHint: 'Exact requesting user; leave blank for any user.',
    search: 'Search sessions',
    refreshSessions: 'Refresh sessions',
    filters: 'Flow and status filters',
    filterHint:
        'Search the server by exact requesting user and flow. Leave a field blank for any value. Filters apply to every page, not just the rows shown here.',
    appliedFilters: 'Showing server results for',
    anyUser: 'any requesting user',
    anyFlow: 'any flow',
    user: 'Requesting user',
    status: 'Status',
    started: 'Started',
    origin: 'Origin',
    active: 'Active (new or authorized)',
    all: 'All statuses',
    new: 'Awaiting authorization',
    authorized: 'Authorized',
    disposed: 'Ended',
    withheld: 'Not returned under this forced-command policy',
    notReported: 'Not reported',
    sessionPending: 'Session metadata will load when this view is active and access is available.',
    sessionsLoading: 'Loading session metadata…',
    detailsLoading: 'Loading session details…',
    sessionsCleared:
        'Session metadata needs refreshing. Use Refresh sessions to inspect the current state.',
    noSessions: 'No sessions were returned on this page for the applied filters.',
    moreSessions: 'More sessions are available. This is one page, not the complete list.',
    page: 'Page',
    snapshot: 'Loaded metadata, not a live connection monitor. Refresh to check for changes.',
    readNext:
        'Check your permissions and connection, then explicitly refresh or search again. Nothing is retried automatically. Any displayed metadata is from the last successful read.',
    readDenied:
        'This sign-in is not permitted to read these details. Other permitted actions remain available.',
    readUnavailable:
        'The server request could not be completed. Previously loaded data has not been refreshed.',
    detailsTitle: 'Session details',
    lastAccessed: 'Last accessed',
    issuer: 'Verified issuer',
    subject: 'Verified subject',
    disconnect: 'Disconnect connections',
    disconnectHint:
        'Close this session’s current connections. The session and its workload remain available for a new connection.',
    end: 'End session',
    endHint:
        'Revoke this session, close its connections, and release its workload and authorization through the backend lifecycle. This can remove resources.',
    direct: 'Advanced: target by ID',
    versionRefresh: 'Refresh server version',
    versionPending: 'The short version will load when this view is active and access is available.',
    versionLoading: 'Loading server version…',
    versionUnavailable:
        'No version was returned. Use Refresh server version to try again with your current permissions.',
    reported: 'Reported by this server; not an independent verification.',
    build: 'Detailed build information',
    buildLoad: 'Load detailed build information',
    buildLoading: 'Loading detailed build information…',
    buildHint:
        'Request vendor, Go, and feature details separately. Your policy may allow only the short version.',
    flowsRefresh: 'Refresh flows',
    flowsPending: 'Configured flows will load after the version request when this view is active.',
    flowsLoading: 'Loading configured flows…',
    flowsUnavailable:
        'No flow page was returned. Use Refresh flows to try again with your current permissions.',
    flowsEmpty: 'No configured flows were returned on this page.',
    moreFlows: 'More flows are available. This is one page, not the complete list.',
} as const;

export const m = (key: keyof typeof messages): string => messages[key];
export const sessionStateLabel = (state: string): string =>
    state === 'active' ||
    state === 'all' ||
    state === 'new' ||
    state === 'authorized' ||
    state === 'disposed'
        ? m(state)
        : state;
