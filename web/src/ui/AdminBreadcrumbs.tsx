import { Breadcrumbs, Link, Typography } from '@mui/material';
import type { ManagementLocation } from './management-location';
import { useManagementNavigation } from './management-navigation';
import { t } from './messages';
import { RouterAnchor } from './RouterAnchor';

export interface AdminCrumb {
  label: string;
  onClick?: () => void;
  disabled?: boolean;
  target?: ManagementLocation;
  to?: string;
}

export function AdminBreadcrumbs({ items }: { items: readonly AdminCrumb[] }) {
  const navigation = useManagementNavigation();
  const keyed: { item: AdminCrumb; key: string }[] = [];
  const path: string[] = [];
  for (const item of items) {
    path.push(item.label);
    keyed.push({ item, key: JSON.stringify(path) });
  }
  return (
    <Breadcrumbs aria-label={t('adminBreadcrumbs')} className="admin-breadcrumbs">
      {keyed.map(({ item, key }, index) => {
        const href = item.to ?? (item.target ? navigation?.href?.(item.target) : undefined);
        return href ? (
          <Link
            key={key}
            component={RouterAnchor}
            to={href}
            underline="hover"
            color="inherit"
            aria-disabled={item.disabled || undefined}
            aria-current={index === items.length - 1 ? 'page' : undefined}
            sx={{ font: 'inherit', lineHeight: 'inherit', verticalAlign: 'baseline' }}
            onClick={(event) => {
              if (item.disabled) {
                event.preventDefault();
                return;
              }
              if (
                item.onClick &&
                !event.ctrlKey &&
                !event.metaKey &&
                !event.shiftKey &&
                !event.altKey &&
                event.button === 0
              ) {
                event.preventDefault();
                item.onClick();
              }
            }}
          >
            {item.label}
          </Link>
        ) : (
          <Typography
            key={key}
            component="span"
            color="text.primary"
            aria-current={index === items.length - 1 ? 'page' : undefined}
          >
            {item.label}
          </Typography>
        );
      })}
    </Breadcrumbs>
  );
}
