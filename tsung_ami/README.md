# Build Tsung 1.7.0 AMI

First, install [Packer](https://www.packer.io/intro/getting-started/install.html).

On macOS:

```sh
brew install packer
```

Second, run:

```sh
packer build packer.json
```

A tsung AMI should be created in the `us-west-2` region (by default) using the
credentials specified by the profile `scalableinternetservices-admin`.
