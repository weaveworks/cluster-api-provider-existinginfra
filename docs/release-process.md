## CAPEI release process

* In order to create a release we need to create a tag and a Github Action will take care of the release where it will use PR's titles as release notes.

```
git checkout master
git fetch
git reset --hard origin/master
git tag -a vX.Y.Z -m vX.Y.Z
git push --tags
```
