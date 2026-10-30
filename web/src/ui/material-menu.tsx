import {
  Divider,
  IconButton,
  ListItemIcon,
  ListItemText,
  ListSubheader,
  Menu as MuiMenu,
  MenuItem as MuiMenuItem,
  Stack,
} from '@mui/material';
import type { ComponentProps, MouseEvent, PointerEvent, ReactElement, ReactNode } from 'react';
import {
  Children,
  cloneElement,
  createContext,
  Fragment,
  isValidElement,
  useContext,
  useEffect,
  useRef,
  useState,
} from 'react';

type Point = { top: number; left: number };
type MenuState = {
  opened: boolean;
  show: (element: HTMLElement | Point) => void;
  close: () => void;
};
const State = createContext<MenuState | null>(null);
function useMenu() {
  const state = useContext(State);
  if (!state) {
    throw new Error('Menu outside its owner');
  }
  return state;
}

function MaterialMenu({
  opened: controlled,
  onChange,
  children,
  returnFocus = true,
  position = 'bottom-start',
  transitionProps: _transition,
}: {
  opened?: boolean;
  onChange?: (value: boolean) => void;
  children: ReactNode;
  returnFocus?: boolean;
  position?: string;
  transitionProps?: { duration: number };
}) {
  const [local, setLocal] = useState(false);
  const [anchor, setAnchor] = useState<HTMLElement | Point | null>(null);
  const opened = controlled ?? local;
  const change = (value: boolean) => {
    if (controlled === undefined) {
      setLocal(value);
    }
    onChange?.(value);
  };
  return (
    <State.Provider
      value={{
        opened,
        show: (target) => {
          setAnchor(target);
          change(true);
        },
        close: () => change(false),
      }}
    >
      <MenuLayout anchor={anchor} returnFocus={returnFocus} position={position}>
        {children}
      </MenuLayout>
    </State.Provider>
  );
}
const Layout = createContext<{
  anchor: HTMLElement | Point | null;
  returnFocus: boolean;
  position: string;
} | null>(null);
function MenuLayout({
  children,
  ...value
}: {
  children: ReactNode;
  anchor: HTMLElement | Point | null;
  returnFocus: boolean;
  position: string;
}) {
  return <Layout.Provider value={value}>{children}</Layout.Provider>;
}
type Trigger = ReactElement<Record<string, unknown>>;
function Target({ children }: { children: Trigger }) {
  const menu = useMenu();
  return cloneElement(children, {
    'aria-haspopup': 'menu',
    'aria-expanded': menu.opened,
    onClick: (event: MouseEvent<HTMLElement>) => {
      (children.props.onClick as ((event: MouseEvent<HTMLElement>) => void) | undefined)?.(event);
      if (!event.defaultPrevented) {
        if (menu.opened) {
          menu.close();
        } else {
          menu.show(event.currentTarget);
        }
      }
    },
  });
}

// Gesture adaptation only; the surface, focus handling and items are MUI Menu.
// Never forward a long-press synthetic click as a separate action.
function ContextMenu({ children, onOpen }: { children: Trigger; onOpen?: () => void }) {
  const menu = useMenu();
  const current = useRef({ menu, onOpen });
  current.current = { menu, onOpen };
  const timer = useRef<ReturnType<typeof setTimeout> | null>(null);
  const origin = useRef<{ id: number; x: number; y: number } | null>(null);
  const touch = useRef<number | null>(null);
  const openingTouch = useRef<AbortController | null>(null);
  const consumed = useRef(false);
  function cancel() {
    if (timer.current !== null) {
      clearTimeout(timer.current);
    }
    timer.current = null;
    origin.current = null;
  }
  useEffect(
    () => () => {
      if (timer.current !== null) {
        clearTimeout(timer.current);
      }
      openingTouch.current?.abort();
    },
    [],
  );
  return cloneElement(children, {
    onContextMenu: (event: MouseEvent<HTMLElement>) => {
      event.preventDefault();
      if (origin.current) {
        consumed.current = true;
      }
      current.current.onOpen?.();
      current.current.menu.show({ top: event.clientY, left: event.clientX });
    },
    onPointerDown: (event: PointerEvent) => {
      cancel();
      consumed.current = false;
      openingTouch.current?.abort();
      touch.current = null;
      if (!event.isPrimary || event.button !== 0 || !['touch', 'pen'].includes(event.pointerType)) {
        return;
      }
      const document = event.currentTarget.ownerDocument;
      origin.current = { id: event.pointerId, x: event.clientX, y: event.clientY };
      timer.current = setTimeout(() => {
        timer.current = null;
        const point = origin.current;
        if (point) {
          consumed.current = true;
          const identifier = touch.current;
          if (identifier !== null) {
            // Opening MUI's portal moves the release target to its backdrop.
            // Cancel only this initial touch's compatibility click, not the next
            // deliberate menu tap (and not scrolling before a long press).
            const controller = new AbortController();
            openingTouch.current = controller;
            const finish = (event: TouchEvent) => {
              if (Array.from(event.changedTouches).some((item) => item.identifier === identifier)) {
                if (event.type === 'touchend') {
                  event.preventDefault();
                }
                controller.abort();
              }
            };
            document.addEventListener('touchend', finish, {
              capture: true,
              passive: false,
              signal: controller.signal,
            });
            document.addEventListener('touchcancel', finish, {
              capture: true,
              signal: controller.signal,
            });
          }
          current.current.onOpen?.();
          current.current.menu.show({ top: point.y, left: point.x });
        }
      }, 500);
    },
    onTouchStart: (event: React.TouchEvent) => {
      touch.current =
        event.touches.length === 1 ? (event.changedTouches[0]?.identifier ?? null) : null;
    },
    onPointerMove: (event: PointerEvent) => {
      const point = origin.current;
      if (
        point &&
        (point.id !== event.pointerId ||
          Math.hypot(point.x - event.clientX, point.y - event.clientY) > 8)
      ) {
        cancel();
      }
    },
    onPointerUp: cancel,
    onPointerCancel: cancel,
    onClickCapture: (event: MouseEvent) => {
      if (consumed.current) {
        consumed.current = false;
        event.preventDefault();
        event.stopPropagation();
      }
    },
  });
}

function Dropdown({
  children,
  'aria-label': label,
}: {
  children: ReactNode;
  'aria-label'?: string;
}) {
  const menu = useMenu();
  const layout = useContext(Layout);
  const anchor = layout?.anchor;
  const point = anchor && 'top' in anchor ? anchor : null;
  return (
    <MuiMenu
      open={menu.opened && anchor !== null}
      onClose={menu.close}
      transitionDuration={0}
      anchorReference={point ? 'anchorPosition' : 'anchorEl'}
      anchorEl={anchor && !point ? (anchor as HTMLElement) : null}
      anchorPosition={point ?? undefined}
      disableRestoreFocus={!layout?.returnFocus}
      anchorOrigin={{
        vertical: 'bottom',
        horizontal: layout?.position.endsWith('end') ? 'right' : 'left',
      }}
      transformOrigin={{
        vertical: 'top',
        horizontal: layout?.position.endsWith('end') ? 'right' : 'left',
      }}
      slotProps={{ list: { 'aria-label': label } }}
    >
      {menuChildren(children)}
    </MuiMenu>
  );
}

function menuChildren(children: ReactNode, prefix = ''): ReactNode[] {
  return Children.toArray(children).flatMap((child, index) => {
    if (!isValidElement<{ children?: ReactNode }>(child)) {
      return [child];
    }
    const key = `${prefix}/${child.key ?? index}`;
    return child.type === Fragment
      ? menuChildren(child.props.children, key)
      : [cloneElement(child, { key })];
  });
}

type ItemProps = Omit<ComponentProps<typeof MuiMenuItem>, 'color'> & {
  color?: string;
  icon?: ReactNode;
  component?: 'a';
  href?: string;
  target?: string;
  rel?: string;
};
function Item({ icon, children, onClick, color, ...props }: ItemProps) {
  const menu = useMenu();
  return (
    <MuiMenuItem
      {...props}
      sx={{ color: color === 'red' ? 'error.main' : undefined }}
      onClick={(event) => {
        onClick?.(event);
        menu.close();
      }}
    >
      {icon && <ListItemIcon>{icon}</ListItemIcon>}
      <ListItemText>{children}</ListItemText>
    </MuiMenuItem>
  );
}

export const Menu = Object.assign(MaterialMenu, {
  Target,
  ContextMenu,
  Dropdown,
  Item,
  Label: ListSubheader,
  Divider,
});

function MaterialActionIcon({
  variant: _variant,
  color,
  size,
  ...props
}: Omit<ComponentProps<typeof IconButton>, 'color' | 'size'> & {
  variant?: string;
  color?: string;
  size?: string;
}) {
  return (
    <IconButton
      {...props}
      size={size === 'lg' ? 'medium' : 'small'}
      color={
        color === 'red'
          ? 'error'
          : color === 'green'
            ? 'success'
            : color === 'yellow'
              ? 'warning'
              : 'default'
      }
    />
  );
}
export const ActionIcon = Object.assign(MaterialActionIcon, {
  Group: (props: ComponentProps<typeof Stack>) => (
    <Stack {...props} direction="row" sx={{ alignItems: 'center' }} />
  ),
});
