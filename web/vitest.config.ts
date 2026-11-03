import { playwright } from '@vitest/browser-playwright';
import { defineConfig } from 'vitest/config';

export default defineConfig({
  optimizeDeps: {
    // Eagerly include the real App/workspace presentation imports: discovering
    // these midway through browser tests otherwise reloads and loses the suite.
    include: [
      '@mui/material',
      '@xterm/addon-fit',
      '@xterm/xterm',
      'react/jsx-dev-runtime',
      ...[
        'Add',
        'ArrowDropDown',
        'Cancel',
        'CheckCircle',
        'Circle',
        'Close',
        'ContentCopy',
        'DeleteOutlineOutlined',
        'Description',
        'KeyboardReturn',
        'LinkOff',
        'Login',
        'Logout',
        'MoreVert',
        'OpenInNew',
        'Palette',
        'PowerSettingsNew',
        'Refresh',
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
