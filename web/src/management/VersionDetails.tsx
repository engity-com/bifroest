import { Link } from '@mui/material';
import type { VersionInfo } from './protocol';

const categories: Readonly<Record<string, string>> = {
  authorization: 'authorization',
  environment: 'environment',
  session: 'session',
  'audit-target': 'auditlog/remote-targets',
};
const entries: Readonly<Record<string, Readonly<Record<string, string>>>> = {
  authorization: {
    bifroest: 'bifroest',
    htpasswd: 'htpasswd',
    local: 'local',
    none: 'none',
    oidc: 'oidc',
    oidcDeviceAuth: 'oidc',
    simple: 'simple',
  },
  environment: {
    docker: 'docker',
    dummy: 'dummy',
    kubernetes: 'kubernetes',
    local: 'local',
    management: 'management',
    ssh: 'ssh',
  },
  session: { fs: 'fs' },
  'audit-target': { s3: 's3', sftp: 'sftp', webdav: 'webdav' },
};
export function documentationLink(
  version: string,
  category: string,
  entry?: string,
): string | null {
  const path = categories[category];
  if (!path) {
    return null;
  }
  const item = entry === undefined ? '' : entries[category]?.[entry.replace(/\[.*$/u, '')];
  if (item === undefined) {
    return null;
  }
  const release =
    /^v?(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$/u.test(
      version,
    )
      ? `v${version.replace(/^v/u, '').split('+')[0]}/`
      : '';
  return `https://bifroest.engity.org/${release}reference/${path}/${item ? `${item}/` : ''}`;
}
export function VersionDetails({ info }: { info: VersionInfo }) {
  const build = info.build;
  if (!build) {
    return <p className="server-version">{info.text}</p>;
  }
  const link = (label: string, category: string, entry?: string) => {
    const href = documentationLink(build.version, category, entry);
    return href ? (
      <Link href={href} target="_blank" rel="noopener noreferrer">
        {label}
      </Link>
    ) : (
      label
    );
  };
  return (
    <section className="stack" aria-label="Build information">
      <dl className="metadata-grid">
        {(
          [
            ['Product', build.title],
            ['Version', build.version],
            ['Revision', build.revision],
            ['Edition', build.edition],
            ['Built', build.buildAt],
            ['Vendor', build.vendor],
            ['Go', build.go],
            ['Platform', build.platform],
          ] as const
        ).map(([label, value]) => (
          <div className="metadata-pair" key={label}>
            <dt>{label}</dt>
            <dd className="identifier">{value}</dd>
          </div>
        ))}
      </dl>
      <dl className="metadata-grid version-features">
        {build.features.map((group) => (
          <div className="metadata-pair" key={group.name}>
            <dt>{link(group.name, group.name)}</dt>
            <dd className="actions">
              {group.entries.map((entry) => (
                <span key={entry}>{link(entry, group.name, entry)}</span>
              ))}
            </dd>
          </div>
        ))}
      </dl>
    </section>
  );
}
