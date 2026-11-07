import { playwright } from '@vitest/browser-playwright';
import { defineConfig } from 'vitest/config';

export default defineConfig({
  optimizeDeps: {
    // Eagerly include the real App/workspace presentation imports: discovering
    // these midway through browser tests otherwise reloads and loses the suite.
    include: [
      '@mui/material',
      '@mui/x-data-grid',
      '@xterm/addon-fit',
      '@xterm/xterm',
      'react/jsx-dev-runtime',
      ...[
        'Add',
        'ArrowDropDown',
        'ArrowBack',
        'BrightnessAutoOutlined',
        'DarkModeOutlined',
        'LightModeOutlined',
        'FactCheckOutlined',
        'FactCheck',
        'ScreenshotMonitor',
        'DeleteForeverOutlined',
        'ClearAllOutlined',
        'Cancel',
        'CheckCircle',
        'ChevronLeft',
        'Circle',
        'Close',
        'ContentCopy',
        'DeleteOutlineOutlined',
        'Description',
        'FilterList',
        'InfoOutlined',
        'KeyboardReturn',
        'HomeOutlined',
        'LinkOff',
        'Login',
        'Logout',
        'MoreVert',
        'Menu',
        'OpenInNew',
        'Palette',
        'PowerSettingsNew',
        'PushPin',
        'PeopleOutlineOutlined',
        'Refresh',
        'Search',
        'Settings',
        'Stop',
        'Visibility',
        'VisibilityOff',
        'WarningAmber',
      ].map((icon) => `@mui/icons-material/${icon}`),
    ],
  },
  test: {
    fileParallelism: false, // Real IndexedDB fixtures deliberately share one database name.
    include: ['test/**/*.test.ts'],
    browser: {
      enabled: true,
      headless: true,
      provider: playwright(),
      instances: [{ browser: 'chromium' }],
    },
  },
});
