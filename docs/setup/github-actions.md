---
description: Install Bifröst in a GitHub Actions job and check your configuration automatically on pushes and pull requests.
---

# Using Bifröst in GitHub Actions

The [Setup Bifröst action](https://github.com/engity-com/bifroest-action)
installs Bifröst, verifies the download and makes `bifroest` available to
later steps in the same job. Use it to run Bifröst commands in a workflow;
it does not start a server.

## Test a configuration on every change {: #configuration-tests }

Commit your `configuration.yaml` and `tests` directory from
[Test a configuration](../guides/testing.md), then save this workflow as
`.github/workflows/bifroest.yml` to check them on each push and pull request:

```yaml title=".github/workflows/bifroest.yml"
name: Bifröst configuration tests
on: [push, pull_request]

permissions:
  contents: read

jobs:
  configuration:
    runs-on: ubuntu-24.04
    steps:
      - name: Check out the configuration and tests
        uses: actions/checkout@v7
        with:
          persist-credentials: false

      - name: Install Bifröst
        uses: engity-com/bifroest-action@v1

      - name: Test the configuration
        # Execute all Bifröst tests inside the repository
        # against configuration.yaml in the root of the repository.
        run: bifroest test -c configuration.yaml .
```

These are offline checks, not login tests. A failed assertion or test error
fails the job; results appear in the run log under your repository's **Actions** tab.

For all settings, outputs, supported runners and security guidance, see the
[action's documentation on GitHub](https://github.com/engity-com/bifroest-action#readme).
