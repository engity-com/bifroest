//go:build darwin

package user

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/google/uuid"

	bsys "github.com/engity-com/bifroest/pkg/sys"
)

type darwinOwnedHome struct {
	parent   *os.Root
	name     string
	expected os.FileInfo
}

type darwinHomeOwnership struct {
	path string
	info os.FileInfo
	uid  uint32
	gid  uint32
}

func (this *darwinOwnedHome) close() {
	if this != nil && this.parent != nil {
		_ = this.parent.Close()
	}
}

func (this *darwinOwnedHome) remove(ctx context.Context) error {
	if this == nil || this.expected == nil {
		return nil
	}
	current, err := this.parent.Lstat(this.name)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	if !os.SameFile(current, this.expected) {
		return fmt.Errorf("home directory %q changed identity before cleanup", this.name)
	}
	home, err := this.parent.OpenRoot(this.name)
	if err != nil {
		return err
	}
	defer home.Close()
	opened, err := home.Stat(".")
	if err != nil {
		return err
	}
	if !os.SameFile(opened, this.expected) {
		return fmt.Errorf("home directory %q changed identity before cleanup", this.name)
	}
	directory, err := home.Open(".")
	if err != nil {
		return err
	}
	entries, readErr := directory.ReadDir(-1)
	closeErr := directory.Close()
	if err := errors.Join(readErr, closeErr); err != nil {
		return err
	}
	for _, entry := range entries {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := home.RemoveAll(entry.Name()); err != nil {
			return err
		}
	}
	current, err = this.parent.Lstat(this.name)
	if err != nil {
		return err
	}
	if !os.SameFile(current, this.expected) {
		return fmt.Errorf("home directory %q changed identity during cleanup", this.name)
	}
	return this.parent.Remove(this.name)
}

func validateDarwinHomePath(home string) (string, error) {
	clean := filepath.Clean(home)
	if home == "" || !filepath.IsAbs(clean) || clean == "/" || filepath.Dir(clean) == "/" {
		return "", fmt.Errorf("refusing to use unsafe home directory %q", home)
	}
	return clean, nil
}

func validateDarwinHomeAncestors(home string, childOwner uint32) error {
	for path := filepath.Dir(home); ; path = filepath.Dir(path) {
		info, err := os.Lstat(path)
		if err != nil {
			return err
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || !info.IsDir() || stat.Uid != 0 ||
			(info.Mode().Perm()&022 != 0 && (info.Mode()&os.ModeSticky == 0 || childOwner != 0)) {
			return fmt.Errorf("unsafe home directory ancestor %q", path)
		}
		if filepath.Dir(path) == path {
			return nil
		}
		childOwner = stat.Uid
	}
}

func ensureDarwinHomeParents(home string, childOwner uint32) error {
	parent := filepath.Dir(home)
	existing := parent
	for {
		info, err := os.Lstat(existing)
		if err == nil {
			if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
				return fmt.Errorf("unsafe home directory ancestor %q", existing)
			}
			break
		}
		if !os.IsNotExist(err) {
			return err
		}
		next := filepath.Dir(existing)
		if next == existing {
			return err
		}
		existing = next
	}
	if err := validateDarwinHomeAncestors(filepath.Join(existing, ".bifroest-home-parent"), 0); err != nil {
		return err
	}
	root, err := os.OpenRoot(existing)
	if err != nil {
		return err
	}
	defer root.Close()
	relative, err := filepath.Rel(existing, parent)
	if err != nil {
		return err
	}
	if relative != "." {
		if err := root.MkdirAll(relative, 0755); err != nil {
			return err
		}
	}
	return validateDarwinHomeAncestors(home, childOwner)
}

func removeDarwinTreeIfSame(path string, expected os.FileInfo) error {
	parent, err := os.OpenRoot(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer parent.Close()
	name := filepath.Base(path)
	actual, err := parent.Lstat(name)
	if err != nil {
		return err
	}
	if !os.SameFile(actual, expected) {
		return fmt.Errorf("path %q changed identity before removal", path)
	}
	return parent.RemoveAll(name)
}

func stageDarwinHomeReplacement(path string, expected os.FileInfo, transaction *darwinMutation) error {
	parent, err := os.OpenRoot(filepath.Dir(path))
	if err != nil {
		return err
	}
	name := filepath.Base(path)
	actual, err := parent.Lstat(name)
	if err != nil || !os.SameFile(actual, expected) {
		_ = parent.Close()
		if err != nil {
			return err
		}
		return fmt.Errorf("path %q changed identity before replacement", path)
	}
	backup := "." + name + ".bifroest-backup-" + uuid.NewString()
	if err := parent.Rename(name, backup); err != nil {
		_ = parent.Close()
		return err
	}
	transaction.onFilesystemRollback(func(context.Context) error {
		defer parent.Close()
		if _, err := parent.Lstat(name); err == nil {
			return fmt.Errorf("refusing to restore Darwin home backup over occupied path %q", path)
		} else if !os.IsNotExist(err) {
			return err
		}
		return parent.Rename(backup, name)
	})
	transaction.onCommit(func(context.Context) error {
		return errors.Join(parent.RemoveAll(backup), parent.Close())
	})
	return nil
}

func snapshotDarwinHomeOwnership(home string) ([]darwinHomeOwnership, error) {
	root, err := os.OpenRoot(home)
	if err != nil {
		return nil, err
	}
	defer root.Close()
	var result []darwinHomeOwnership
	err = fs.WalkDir(root.FS(), ".", func(path string, _ fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		info, err := root.Lstat(path)
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("refusing to snapshot ownership through symlink %q", path)
		}
		if !info.IsDir() && !info.Mode().IsRegular() {
			return fmt.Errorf("refusing to change ownership of special home entry %q", path)
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok {
			return fmt.Errorf("cannot inspect ownership of home entry %q", path)
		}
		if info.Mode().IsRegular() && stat.Nlink > 1 {
			return fmt.Errorf("refusing to change ownership of multiply linked home entry %q", path)
		}
		result = append(result, darwinHomeOwnership{path: path, info: info, uid: stat.Uid, gid: stat.Gid})
		return nil
	})
	return result, err
}

func restoreDarwinHomeOwnership(ctx context.Context, home string, ownership []darwinHomeOwnership) error {
	root, err := os.OpenRoot(home)
	if err != nil {
		return err
	}
	defer root.Close()
	var result error
	for _, entry := range ownership {
		if err := ctx.Err(); err != nil {
			return errors.Join(result, err)
		}
		info, err := root.Lstat(entry.path)
		if err != nil || !os.SameFile(info, entry.info) {
			if err == nil {
				err = fmt.Errorf("home entry %q changed identity before ownership rollback", entry.path)
			}
			result = errors.Join(result, err)
			continue
		}
		opened, err := root.Open(entry.path)
		if err != nil {
			result = errors.Join(result, err)
			continue
		}
		openedInfo, statErr := opened.Stat()
		if statErr != nil || !os.SameFile(info, openedInfo) {
			if statErr == nil {
				statErr = fmt.Errorf("home entry %q changed identity before ownership rollback", entry.path)
			}
			result = errors.Join(result, statErr, opened.Close())
			continue
		}
		result = errors.Join(result, opened.Chown(int(entry.uid), int(entry.gid)), opened.Close())
	}
	return result
}

func (this *DarwinRepository) prepareDarwinHomeRemoval(ctx context.Context, record *darwinUserRecord) (*darwinOwnedHome, error) {
	home, err := validateDarwinHomePath(record.homeDir)
	if err != nil {
		return nil, err
	}
	users, err := this.allLocalUsers(ctx)
	if err != nil {
		return nil, err
	}
	if err := rejectDarwinHomeOverlap(home, record.name, users); err != nil {
		return nil, err
	}
	parent, err := os.OpenRoot(filepath.Dir(home))
	if os.IsNotExist(err) {
		return &darwinOwnedHome{}, nil
	}
	if err != nil {
		return nil, err
	}
	result := &darwinOwnedHome{parent: parent, name: filepath.Base(home)}
	info, err := parent.Lstat(result.name)
	if os.IsNotExist(err) {
		return result, nil
	}
	if err != nil {
		result.close()
		return nil, err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.IsDir() || stat.Uid != uint32(record.uid) {
		result.close()
		return nil, fmt.Errorf("home directory %q is not exclusively owned by account %q", home, record.name)
	}
	if err := validateDarwinHomeAncestors(home, stat.Uid); err != nil {
		result.close()
		return nil, err
	}
	result.expected = info
	return result, nil
}

func (this *DarwinRepository) createDarwinHome(ctx context.Context, name string, uid Id, gid GroupId, skel, home string, onExist EnsureOnHomeDirExist, transaction *darwinMutation) error {
	home, err := validateDarwinHomePath(home)
	if err != nil {
		return err
	}
	if err := this.ensureDarwinHomeNotShared(ctx, home, name); err != nil {
		return err
	}
	info, err := os.Lstat(home)
	if err == nil {
		if !info.IsDir() {
			return fmt.Errorf("home directory %q exists but is not a directory", home)
		}
		switch onExist {
		case EnsureOnHomeDirExistTakeover:
			stat, ok := info.Sys().(*syscall.Stat_t)
			if !ok {
				return fmt.Errorf("cannot inspect owner of home directory %q", home)
			}
			if err := validateDarwinHomeAncestors(home, stat.Uid); err != nil {
				return err
			}
			ownership, err := snapshotDarwinHomeOwnership(home)
			if err != nil {
				return err
			}
			transaction.onFilesystemRollback(func(ctx context.Context) error {
				return restoreDarwinHomeOwnership(ctx, home, ownership)
			})
			return this.chownDarwinHome(ctx, home, uid, gid)
		case EnsureOnHomeDirExistOverwrite:
			stat, ok := info.Sys().(*syscall.Stat_t)
			if !ok || stat.Uid != uint32(uid) {
				return fmt.Errorf("refusing to overwrite home directory %q not owned by UID %d", home, uid)
			}
			if err := validateDarwinHomeAncestors(home, stat.Uid); err != nil {
				return err
			}
			if err := stageDarwinHomeReplacement(home, info, transaction); err != nil {
				return err
			}
		default:
			return fmt.Errorf("home directory %q already exists", home)
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	if err := ensureDarwinHomeParents(home, uint32(uid)); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	parent, err := os.OpenRoot(filepath.Dir(home))
	if err != nil {
		return err
	}
	defer parent.Close()
	if err := parent.Mkdir(filepath.Base(home), 0700); err != nil {
		return fmt.Errorf("cannot create Darwin home directory %q: %w", home, err)
	}
	created, err := parent.Lstat(filepath.Base(home))
	if err != nil {
		return err
	}
	transaction.onFilesystemRollback(func(ctx context.Context) error {
		return removeDarwinTreeIfSame(home, created)
	})
	if skel != "" {
		if err := copyDarwinSkeleton(ctx, skel, home); err != nil {
			return fmt.Errorf("cannot copy Darwin skeleton %q: %w", skel, err)
		}
	}
	return this.chownDarwinHome(ctx, home, uid, gid)
}

func (this *DarwinRepository) moveDarwinHome(ctx context.Context, name string, oldUID, newUID Id, gid GroupId, oldHome, newHome string, onExist EnsureOnHomeDirExist, transaction *darwinMutation) error {
	oldHome, err := validateDarwinHomePath(oldHome)
	if err != nil {
		return err
	}
	newHome, err = validateDarwinHomePath(newHome)
	if err != nil {
		return err
	}
	if err := this.ensureDarwinHomeNotShared(ctx, oldHome, name); err != nil {
		return err
	}
	if err := this.ensureDarwinHomeNotShared(ctx, newHome, name); err != nil {
		return err
	}
	oldInfo, err := os.Lstat(oldHome)
	if os.IsNotExist(err) {
		return this.createDarwinHome(ctx, name, newUID, gid, "", newHome, onExist, transaction)
	}
	if err != nil {
		return err
	}
	oldStat, ok := oldInfo.Sys().(*syscall.Stat_t)
	if !ok || !oldInfo.IsDir() || oldStat.Uid != uint32(oldUID) {
		return fmt.Errorf("refusing to move home directory %q not owned by UID %d", oldHome, oldUID)
	}
	if err := validateDarwinHomeAncestors(oldHome, oldStat.Uid); err != nil {
		return err
	}
	oldOwnership, err := snapshotDarwinHomeOwnership(oldHome)
	if err != nil {
		return err
	}
	if destination, err := os.Lstat(newHome); err == nil {
		if !destination.IsDir() {
			return fmt.Errorf("home directory %q exists but is not a directory", newHome)
		}
		switch onExist {
		case EnsureOnHomeDirExistTakeover:
			stat, ok := destination.Sys().(*syscall.Stat_t)
			if !ok {
				return fmt.Errorf("cannot inspect owner of home directory %q", newHome)
			}
			if err := validateDarwinHomeAncestors(newHome, stat.Uid); err != nil {
				return err
			}
			ownership, err := snapshotDarwinHomeOwnership(newHome)
			if err != nil {
				return err
			}
			transaction.onFilesystemRollback(func(ctx context.Context) error {
				return restoreDarwinHomeOwnership(ctx, newHome, ownership)
			})
			return this.chownDarwinHome(ctx, newHome, newUID, gid)
		case EnsureOnHomeDirExistOverwrite:
			stat, ok := destination.Sys().(*syscall.Stat_t)
			if !ok || (stat.Uid != uint32(oldUID) && stat.Uid != uint32(newUID)) {
				return fmt.Errorf("refusing to overwrite home directory %q with unexpected owner", newHome)
			}
			if err := validateDarwinHomeAncestors(newHome, stat.Uid); err != nil {
				return err
			}
			if err := stageDarwinHomeReplacement(newHome, destination, transaction); err != nil {
				return err
			}
		default:
			return fmt.Errorf("home directory %q already exists", newHome)
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	if err := ensureDarwinHomeParents(newHome, uint32(newUID)); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := os.Rename(oldHome, newHome); err != nil {
		return fmt.Errorf("cannot move Darwin home directory from %q to %q: %w", oldHome, newHome, err)
	}
	transaction.onFilesystemRollback(func(rollbackCtx context.Context) error {
		current, err := os.Lstat(newHome)
		if err != nil {
			return err
		}
		if !os.SameFile(current, oldInfo) {
			return fmt.Errorf("moved home %q changed identity before rollback", newHome)
		}
		if err := os.Rename(newHome, oldHome); err != nil {
			return err
		}
		return restoreDarwinHomeOwnership(rollbackCtx, oldHome, oldOwnership)
	})
	return this.chownDarwinHome(ctx, newHome, newUID, gid)
}

func (this *DarwinRepository) chownDarwinHome(ctx context.Context, home string, uid Id, gid GroupId) error {
	if home == "" {
		return nil
	}
	home, err := validateDarwinHomePath(home)
	if err != nil {
		return err
	}
	root, err := os.OpenRoot(home)
	if err != nil {
		return err
	}
	defer root.Close()
	return fs.WalkDir(root.FS(), ".", func(path string, entry fs.DirEntry, err error) error {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return ctxErr
		}
		if err != nil {
			return err
		}
		info, err := root.Lstat(path)
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("refusing to change ownership through symlink %q", path)
		}
		if !info.IsDir() && !info.Mode().IsRegular() {
			return fmt.Errorf("refusing to change ownership of special home entry %q", path)
		}
		opened, err := root.Open(path)
		if err != nil {
			return err
		}
		openedInfo, err := opened.Stat()
		if err != nil {
			_ = opened.Close()
			return err
		}
		if !os.SameFile(info, openedInfo) {
			_ = opened.Close()
			return fmt.Errorf("home entry %q changed identity before ownership update", path)
		}
		if stat, ok := openedInfo.Sys().(*syscall.Stat_t); !ok || openedInfo.Mode().IsRegular() && stat.Nlink > 1 {
			_ = opened.Close()
			return fmt.Errorf("refusing to change ownership of multiply linked home entry %q", path)
		}
		return errors.Join(opened.Chown(int(uid), int(gid)), opened.Close())
	})
}

func (this *DarwinRepository) chownOwnedDarwinHome(ctx context.Context, home string, oldUID, newUID Id, gid GroupId) error {
	home, err := validateDarwinHomePath(home)
	if err != nil {
		return err
	}
	info, err := os.Lstat(home)
	if err != nil {
		return err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.IsDir() || stat.Uid != uint32(oldUID) {
		return fmt.Errorf("refusing to change ownership of home directory %q not owned by UID %d", home, oldUID)
	}
	if err := validateDarwinHomeAncestors(home, stat.Uid); err != nil {
		return err
	}
	return this.chownDarwinHome(ctx, home, newUID, gid)
}

func (this *DarwinRepository) ensureDarwinHomeNotShared(ctx context.Context, home, accountName string) error {
	users, err := this.allLocalUsers(ctx)
	if err != nil {
		return err
	}
	return rejectDarwinHomeOverlap(filepath.Clean(home), accountName, users)
}

func rejectDarwinHomeOverlap(home, accountName string, users []*darwinUserRecord) error {
	canonicalHome, err := bsys.CanonicalPath(home)
	if err != nil {
		return err
	}
	for _, candidate := range users {
		if candidate.name == accountName || candidate.homeDir == "" {
			continue
		}
		candidateHome, err := bsys.CanonicalPath(candidate.homeDir)
		if err != nil {
			return err
		}
		if homeInfo, homeErr := os.Stat(canonicalHome); homeErr == nil {
			if candidateInfo, candidateErr := os.Stat(candidateHome); candidateErr == nil && os.SameFile(homeInfo, candidateInfo) {
				return fmt.Errorf("refusing to use shared home directory %q also used by account %q", home, candidate.name)
			}
		}
		comparisonHome := strings.ToLower(canonicalHome)
		comparisonCandidate := strings.ToLower(candidateHome)
		relative, err := filepath.Rel(comparisonHome, comparisonCandidate)
		if err == nil && relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
			return fmt.Errorf("refusing to use shared home directory %q containing home of account %q", home, candidate.name)
		}
		relative, err = filepath.Rel(comparisonCandidate, comparisonHome)
		if err == nil && relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
			return fmt.Errorf("refusing to use shared home directory %q inside home of account %q", home, candidate.name)
		}
	}
	return nil
}

func copyDarwinSkeleton(ctx context.Context, source, destination string) error {
	root, err := filepath.Abs(source)
	if err != nil {
		return err
	}
	info, err := os.Lstat(root)
	if err != nil {
		return err
	}
	if !info.IsDir() {
		return fmt.Errorf("skeleton is not a directory")
	}
	sourceRoot, err := os.OpenRoot(root)
	if err != nil {
		return err
	}
	defer sourceRoot.Close()
	openedRoot, err := sourceRoot.Stat(".")
	if err != nil {
		return err
	}
	if !os.SameFile(info, openedRoot) {
		return fmt.Errorf("skeleton changed identity before copy")
	}
	destinationRoot, err := os.OpenRoot(destination)
	if err != nil {
		return err
	}
	defer destinationRoot.Close()
	return fs.WalkDir(sourceRoot.FS(), ".", func(path string, _ fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if path == "." {
			return nil
		}
		entryInfo, err := sourceRoot.Lstat(path)
		if err != nil {
			return err
		}
		if entryInfo.Mode()&os.ModeSymlink != 0 || (!entryInfo.Mode().IsRegular() && !entryInfo.IsDir()) {
			return fmt.Errorf("unsupported skeleton entry %q", path)
		}
		if entryInfo.IsDir() {
			return destinationRoot.Mkdir(path, entryInfo.Mode().Perm())
		}
		input, err := sourceRoot.Open(path)
		if err != nil {
			return err
		}
		openedInfo, err := input.Stat()
		if err != nil || !os.SameFile(entryInfo, openedInfo) {
			_ = input.Close()
			if err != nil {
				return err
			}
			return fmt.Errorf("skeleton entry %q changed identity before copy", path)
		}
		output, err := destinationRoot.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, entryInfo.Mode().Perm())
		if err != nil {
			_ = input.Close()
			return err
		}
		_, copyErr := io.Copy(output, input)
		return errors.Join(copyErr, output.Close(), input.Close())
	})
}
