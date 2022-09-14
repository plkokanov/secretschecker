## SecretsChecker

You can use the SecretsChecker to check if all of the data entries for `Shoot` secrets generated and stored in the `ShootState` of a `Shoot` cluster match the secrets in the `Shoot`'s control plane

## Using the tool

First, build the `secretschecker` binary locally by executing:
```bash
make build
```
The binary will be located under `./bin/secretschecker`

To check which secrets in a `Shoot`'s control plane do not match their respective data entries in the `ShootState` run:
```bash
./bin/secretschecker --config ./example/config.yaml
```
This will check all `Shoot` clusters in your landscape.

If you want to check only the secrets of a specific `Shoot`, run:
```bash
./bin/secretschecker --config ./example/config.yaml --namespace <project-namespace> --shoot <shoot-name>
```

If you want to sync all secrets from the `Shoot`'s control plane to the `ShootState`, run (***Warning**: make sure to backup the `Shoot`'s `ShootState` before running this command*):
```bash
./bin/secretschecker --config ./example/config.yaml --namespace <project-namespace> --shoot <shoot-name> --sync-to-shootstate
```

Omitting the `--shoot` and `--project-namespace` will cause the secrets of all `Shoot`s to be synced.