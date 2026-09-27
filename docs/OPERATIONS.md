# Operations

Health: `/shield/v1/health`. Admin configuration check: `/shield/admin/health`. Independent verifier UI: `/verify`. Custody: `/shield/evidence/{id}/custody`. Void is append-only: `/shield/evidence/{id}/void`; it preserves the original.

## Consistent backup and restore

Stop incoming writes before making a backup: pause the service or take it offline, and keep it stopped until the command finishes. The SQLite snapshot and original files must represent the same capture state. Run from `/app` on the service with `/data` mounted:

```sh
python -m app.backup backup --database /data/shield.db --storage /data/storage --archive /data/shield-backup.zip
python -m app.backup verify --archive /data/shield-backup.zip
```

Copy the verified archive **off the Render disk** to a private backup destination. Do not use the same disk as the only backup. The archive contains account password hashes, evidence, and original photographs; restrict access and encrypt it in your backup destination. Keep the JWT signing secret separately and securely so existing tokens can be honored after restore, or rotate it to invalidate them.

Restore only while the service is stopped, to empty paths (for example, a replacement disk):

```sh
python -m app.backup restore --archive shield-backup.zip --database /data/shield.db --storage /data/storage
python -m app.backup verify --archive shield-backup.zip
```

The command checks every archived file hash, SQLite integrity, and every evidence row's original photo hash before writing restored files. It refuses to overwrite an existing database or storage directory. Start the service only after checking its health and a sample evidence record. Exercise this sequence on a test disk before collecting real evidence.
