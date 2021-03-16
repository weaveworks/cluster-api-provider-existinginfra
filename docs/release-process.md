# Releasing

We use [GoReleaser](https://goreleaser.com/) to generate release artifacts, which is initiated when a tag pushed to the repository.

## Tagging
The tag we use in the repository follows [semver](https://github.com/semver/semver/blob/master/semver.md) with the leading **v**. We want the tag to be signed by the person creating it.

``` shell
git checkout <branch>
git fetch
git reset --hard origin/<branch>
git tag -s -a vMajor.Minor.patch[-(alpha,beta,rc).#]
git push origin <tag>
```