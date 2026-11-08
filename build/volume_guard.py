"""Refuse an unfamiliar volume layout before the supervisor can write state.

Only directory metadata is inspected. No legacy pier/key payload is opened,
renamed, removed or automatically adopted.
"""

import os
import sys
import stat


def main(argv=None, *, root='/urbit'):
    try:
        descriptor = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            with os.scandir(descriptor) as entries:
                layout = {entry.name: entry.is_dir(follow_symlinks=False) for entry in entries}
            required = {'pier', 'uploads', 'control'}
            if layout and (set(layout) not in (required, required | {'legacy015-evidence'}) or
                           not all(layout.values())):
                raise ValueError('unsupported layout')
            if 'legacy015-evidence' in layout:
                # Native 0.1.6 creates this private service-owned evidence root.
                # It is opaque history, not a pier to adopt or data to relocate.
                evidence = os.open('legacy015-evidence', os.O_RDONLY | os.O_DIRECTORY |
                                   os.O_NOFOLLOW, dir_fd=descriptor)
                try:
                    info = os.fstat(evidence)
                    if info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) & 0o077:
                        raise ValueError('unsafe evidence root')
                finally:
                    os.close(evidence)
            if layout:
                control = os.open('control', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                                  dir_fd=descriptor)
                try:
                    native_markers = {'legacy-recovery-state.json', 'native-file-status.json'} & set(os.listdir(control))
                finally:
                    os.close(control)
                if 'legacy015-evidence' in layout or native_markers:
                    from legacy_evidence import validate_native_history
                    validate_native_history(*(os.path.join(root, name) for name in
                                              ('pier', 'uploads', 'control')))
            if not layout:
                # Establish the whole layout before pending certificate enrollment;
                # otherwise a first-run restart could see only control/ and refuse.
                for name in ('pier', 'uploads', 'control'):
                    os.mkdir(name, mode=0o700, dir_fd=descriptor)
                os.fsync(descriptor)
        finally:
            os.close(descriptor)
    except (OSError, ValueError, TypeError, KeyError, AttributeError):
        print('VOLUME_LAYOUT_REFUSED: preserve the volume; follow the documented migration procedure.', file=sys.stderr)
        return 78
    args = sys.argv[1:] if argv is None else argv
    os.execv(sys.executable, [sys.executable, '/opt/importer/package_service.py', *args])


if __name__ == '__main__':
    sys.exit(main())
