import { Breadcrumbs, Link, Typography } from '@mui/material';
import { t } from './messages';

export interface AdminCrumb {
  label: string;
  onClick?: () => void;
  disabled?: boolean;
}

export function AdminBreadcrumbs({ items }: { items: readonly AdminCrumb[] }) {
  const keyed: { item: AdminCrumb; key: string }[] = [];
  const path: string[] = [];
  for (const item of items) {
    path.push(item.label);
    keyed.push({ item, key: JSON.stringify(path) });
  }
  return (
    <Breadcrumbs aria-label={t('adminBreadcrumbs')} className="admin-breadcrumbs">
      {keyed.map(({ item, key }, index) =>
        item.onClick && index < items.length - 1 ? (
          <Link
            key={key}
            component="button"
            type="button"
            underline="hover"
            color="inherit"
            disabled={item.disabled}
            onClick={item.onClick}
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
        ),
      )}
    </Breadcrumbs>
  );
}
