package environment

import (
	"encoding/csv"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/docker/go-units"
	"github.com/moby/moby/api/types/mount"
)

// parseDockerMount converts one configured --mount-style entry into an API mount.
// The daemon validates paths and mount-specific constraints when creating the container.
func parseDockerMount(raw string) (mount.Mount, error) {
	if strings.TrimSpace(raw) == "" {
		return mount.Mount{}, fmt.Errorf("empty mount")
	}
	reader := csv.NewReader(strings.NewReader(strings.TrimSpace(raw)))
	fields, err := reader.Read()
	if err != nil {
		return mount.Mount{}, fmt.Errorf("invalid mount: %w", err)
	}
	if _, err := reader.Read(); err != io.EOF {
		return mount.Mount{}, fmt.Errorf("mount must contain exactly one entry")
	}
	result := mount.Mount{Type: mount.TypeVolume}
	type field struct {
		key, value string
		hasValue   bool
	}
	options := make([]field, 0, len(fields))
	for _, part := range fields {
		key, value, hasValue := strings.Cut(part, "=")
		if key == "" || strings.TrimSpace(key) != key || (hasValue && (value == "" || strings.TrimSpace(value) != value)) {
			return mount.Mount{}, fmt.Errorf("invalid mount option %q", part)
		}
		key = strings.ToLower(key)
		if !hasValue && key != "ro" && key != "readonly" && key != "volume-nocopy" && key != "bind-create-src" {
			return mount.Mount{}, fmt.Errorf("mount option %q requires a value", key)
		}
		if key == "type" {
			result.Type = mount.Type(strings.ToLower(value))
		} else {
			options = append(options, field{key, value, hasValue})
		}
	}
	switch result.Type {
	case mount.TypeBind, mount.TypeVolume, mount.TypeTmpfs, mount.TypeImage, mount.TypeCluster:
	default:
		return mount.Mount{}, fmt.Errorf("unsupported mount type %q", result.Type)
	}
	for _, option := range options {
		key, value := option.key, option.value
		switch key {
		case "source", "src":
			result.Source = value
			if strings.HasPrefix(value, ".") && !filepath.IsAbs(value) {
				if absolute, err := filepath.Abs(value); err == nil {
					result.Source = absolute
				}
			}
		case "target", "dst", "destination":
			result.Target = value
		case "ro", "readonly":
			result.ReadOnly, err = dockerMountBool(key, value, option.hasValue)
		case "consistency":
			result.Consistency = mount.Consistency(strings.ToLower(value))
		case "bind-propagation", "bind-recursive", "bind-create-src", "bind-nonrecursive":
			if result.Type != mount.TypeBind {
				return mount.Mount{}, fmt.Errorf("mount option %q requires type=bind", key)
			}
			if key == "bind-nonrecursive" {
				return mount.Mount{}, fmt.Errorf("bind-nonrecursive is deprecated; use bind-recursive=disabled")
			}
			if result.BindOptions == nil {
				result.BindOptions = &mount.BindOptions{}
			}
			switch key {
			case "bind-propagation":
				result.BindOptions.Propagation = mount.Propagation(strings.ToLower(value))
			case "bind-recursive":
				result.BindOptions.NonRecursive = false
				result.BindOptions.ReadOnlyNonRecursive = false
				result.BindOptions.ReadOnlyForceRecursive = false
				switch value {
				case "enabled":
				case "disabled":
					result.BindOptions.NonRecursive = true
				case "writable":
					result.BindOptions.ReadOnlyNonRecursive = true
				case "readonly":
					result.BindOptions.ReadOnlyForceRecursive = true
				default:
					return mount.Mount{}, fmt.Errorf("invalid bind-recursive value %q", value)
				}
			case "bind-create-src":
				result.BindOptions.CreateMountpoint, err = dockerMountBool(key, value, option.hasValue)
			}
		case "volume-nocopy", "volume-subpath", "volume-label", "volume-driver", "volume-opt":
			if result.Type != mount.TypeVolume {
				return mount.Mount{}, fmt.Errorf("mount option %q requires type=volume", key)
			}
			if result.VolumeOptions == nil {
				result.VolumeOptions = &mount.VolumeOptions{}
			}
			switch key {
			case "volume-nocopy":
				result.VolumeOptions.NoCopy, err = dockerMountBool(key, value, option.hasValue)
			case "volume-subpath":
				result.VolumeOptions.Subpath = value
			case "volume-driver":
				if result.VolumeOptions.DriverConfig == nil {
					result.VolumeOptions.DriverConfig = &mount.Driver{}
				}
				result.VolumeOptions.DriverConfig.Name = value
			case "volume-label":
				name, label, _ := strings.Cut(value, "=")
				if name == "" {
					return mount.Mount{}, fmt.Errorf("invalid volume-label %q", value)
				}
				if result.VolumeOptions.Labels == nil {
					result.VolumeOptions.Labels = make(map[string]string)
				}
				result.VolumeOptions.Labels[name] = label
			case "volume-opt":
				name, optionValue, _ := strings.Cut(value, "=")
				if name == "" {
					return mount.Mount{}, fmt.Errorf("invalid volume-opt %q", value)
				}
				if result.VolumeOptions.DriverConfig == nil {
					result.VolumeOptions.DriverConfig = &mount.Driver{}
				}
				if result.VolumeOptions.DriverConfig.Options == nil {
					result.VolumeOptions.DriverConfig.Options = make(map[string]string)
				}
				result.VolumeOptions.DriverConfig.Options[name] = optionValue
			}
		case "image-subpath":
			if result.Type != mount.TypeImage {
				return mount.Mount{}, fmt.Errorf("mount option %q requires type=image", key)
			}
			result.ImageOptions = &mount.ImageOptions{Subpath: value}
		case "tmpfs-size", "tmpfs-mode":
			if result.Type != mount.TypeTmpfs {
				return mount.Mount{}, fmt.Errorf("mount option %q requires type=tmpfs", key)
			}
			if result.TmpfsOptions == nil {
				result.TmpfsOptions = &mount.TmpfsOptions{}
			}
			if key == "tmpfs-size" {
				result.TmpfsOptions.SizeBytes, err = units.RAMInBytes(value)
			} else {
				var mode uint64
				mode, err = strconv.ParseUint(value, 8, 32)
				result.TmpfsOptions.Mode = os.FileMode(mode)
			}
		default:
			return mount.Mount{}, fmt.Errorf("unknown mount option %q", key)
		}
		if err != nil {
			return mount.Mount{}, fmt.Errorf("invalid mount option %q: %w", key, err)
		}
	}
	if bind := result.BindOptions; bind != nil {
		if bind.ReadOnlyNonRecursive && !result.ReadOnly {
			return mount.Mount{}, fmt.Errorf("bind-recursive=writable requires readonly")
		}
		if bind.ReadOnlyForceRecursive && (!result.ReadOnly || bind.Propagation != mount.PropagationRPrivate) {
			return mount.Mount{}, fmt.Errorf("bind-recursive=readonly requires readonly and bind-propagation=rprivate")
		}
	}
	return result, nil
}

func dockerMountBool(key, value string, hasValue bool) (bool, error) {
	if !hasValue || value == "1" || value == "true" {
		return true, nil
	}
	if value == "0" || value == "false" {
		return false, nil
	}
	return false, fmt.Errorf("%s must be true, false, 1 or 0", key)
}
