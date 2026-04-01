# Solved Output

## Behavior

- Chat output starts with `flag: ...`
- The next line is `wp_package_path: ...`
- The follow-up explanation stays short

## Default export root

- `./agent-wp`

Folder naming:

- `<category>_<title>_wp`

## Exported files

- `flag.txt`
- `wp.md`
- `poc.md`
- `meta.json`
- `code/`

## Failure handling

- Export failures do not downgrade a solved run
- `wp_warning` is added when export metadata exists but file export fails
