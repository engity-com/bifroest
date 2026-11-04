import { Breadcrumbs, Link, Typography } from '@mui/material';
import { t } from './messages';

export interface AdminCrumb {
  label: string;
  onClick?: () => void;
  disabled?: boolean;
}

export function AdminBreadcrumbs({ items }: { items: readonly AdminCrumb[] }) {
  return (
    <Breadcrumbs aria-label={t('adminBreadcrumbs')} className="admin-breadcrumbs">
      {items.map((item, index) =>
        item.onClick && index < items.length - 1 ? (
          <Link
            key={item.label}
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
            key={item.label}
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
