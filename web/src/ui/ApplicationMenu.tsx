import ClearAllIcon from '@mui/icons-material/ClearAllOutlined';
import DeleteForeverIcon from '@mui/icons-material/DeleteForeverOutlined';
import DescriptionIcon from '@mui/icons-material/Description';
import MoreVertIcon from '@mui/icons-material/MoreVert';
import { ActionIcon, Menu } from './material';
import { t } from './messages';

export function ApplicationMenu({
  opened,
  onChange,
  closeDisabled,
  resetDisabled,
  onCloseAll,
  onReset,
}: {
  opened: boolean;
  onChange(value: boolean): void;
  closeDisabled: boolean;
  resetDisabled: boolean;
  onCloseAll(): void;
  onReset(): void;
}) {
  return (
    <Menu opened={opened} onChange={onChange} position="bottom-end">
      <Menu.Target>
        <ActionIcon variant="subtle" color="gray" size="lg" aria-label={t('applicationMenu')}>
          <MoreVertIcon />
        </ActionIcon>
      </Menu.Target>
      <Menu.Dropdown>
        <Menu.Item
          icon={<ClearAllIcon fontSize="small" />}
          disabled={closeDisabled}
          onClick={onCloseAll}
        >
          {t('closeAllSessions')}
        </Menu.Item>
        <Menu.Item
          icon={<DeleteForeverIcon fontSize="small" />}
          disabled={resetDisabled}
          onClick={onReset}
        >
          {t('resetAllSettings')}
        </Menu.Item>
        <Menu.Divider />
        <Menu.Item
          component="a"
          icon={<DescriptionIcon fontSize="small" />}
          href="/_bifroest/files/third-party-licenses.txt"
          target="_blank"
          rel="noopener noreferrer"
        >
          {t('notices')}
        </Menu.Item>
      </Menu.Dropdown>
    </Menu>
  );
}
