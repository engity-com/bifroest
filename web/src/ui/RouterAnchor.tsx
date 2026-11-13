import { type AnchorHTMLAttributes, forwardRef } from 'react';
import { Link, useInRouterContext } from 'react-router';

// Keep native anchor semantics (copy/open/bookmark) in embedded views too.
export const RouterAnchor = forwardRef<
    HTMLAnchorElement,
    AnchorHTMLAttributes<HTMLAnchorElement> & { to: string }
>(function RouterAnchor({ to, ...props }, ref) {
    return useInRouterContext() ? (
        <Link {...props} to={to} ref={ref} />
    ) : (
        <a {...props} href={to} ref={ref} />
    );
});
