## SecretsChecker

You can use the SecretsChecker to check if all of the data entries for shoot secrets generated and stored in the `ShootState` of a shoot cluster match the secrets in the shoot's control plane

## How to use it
To run the tool locally export the path to the kubeconfig of your garden cluster and then call `make start`. The required configuration file (./example/config.yaml) is automatically provided to the tool when when `make start` is called
```
$ export KUBECONFIG=/path/to/kubeconfig.yaml
$ make start
```