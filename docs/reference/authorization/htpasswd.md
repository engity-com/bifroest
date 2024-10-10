---
toc_depth: 3
description: How to authorize a requesting user via credentials stored in htpasswd format with Bifröst.
---

# Htpasswd authorization

Authorizes a requesting user via credentials stored in [htpasswd format](#format).

## Properties

<<property("type", "Authorization Type", default="htpasswd", required=True)>>
Has to be set to `htpasswd` to enable the htpasswd authorization.

<<property("file", "File Path", "../data-type.md#file-path", default="<os specific>")>>
A file where each line contains an entry in [htpasswd format](#format).

The default value varies depending on the platform Bifröst runs on:

* Linux: `/etc/engity/bifroest/htpasswd`
* Window: `C:\ProgramData\Engity\Bifroest\htpasswd`

#### Examples {: id=property-file-examples }
```{.yaml title="/etc/engity/bifroest/htpasswd"}
foo:$apr1$zapgfl56$eXIHR/wBYFypkUEXWdCZN/
bar:$apr1$wqkvo7c2$dqi5g.hK67jLMY4SJzrjq.
```

<<property("entries", "string")>>

This is similar to [`file`](#property-file), but does contain the [htpasswd entries](#format) directly inside the configuration.

#### Examples {: id=property-entries-examples }
```yaml
authorization:
  type: htpasswd
  entries: |
    foo:$apr1$zapgfl56$eXIHR/wBYFypkUEXWdCZN/
    bar:$apr1$wqkvo7c2$dqi5g.hK67jLMY4SJzrjq.
```

## Format

htpasswd is a format created for [Apache HTTP Server](https://httpd.apache.org/) to enable an easy way to configure [Basic Authentication](https://en.wikipedia.org/wiki/Basic_access_authentication) for web servers. Nowadays it is used in more web server projects than just the Apache HTTP Server and also in other project type like Bifröst. The reason: There is a huge toolset available to create those files.

## Tools

1. [Apache HTTP Server command line tool](https://httpd.apache.org/docs/2.4/programs/htpasswd.html) which can be easily installed on many systems such as:
    * Ubuntu:
      ```shell
      sudo apt-get install apache2-utils -y
      ```
    * Fedora/RedHat:
      ```shell
      sudo apt install apache2-utils -y
      ```
* [Helm for Kubernetes function](https://helm.sh/docs/chart_template_guide/function_list/#htpasswd)
* [Ansible module](https://docs.ansible.com/ansible/latest/collections/community/general/htpasswd_module.html)
* [Terraform/OpenTofu plugin](https://registry.terraform.io/providers/loafoe/htpasswd/latest/docs/resources/password)
* ...

## Context

This authorization will produce a context of type [Authorization Htpasswd](../context/authorization.md#htpasswd).

## Examples

1. Using [dedicated file](#property-file) from default location:
   ```yaml
   type: htpasswd
   ```
2. Using [dedicated file](#property-file) from custom location:
   ```yaml
   type: htpasswd
   file: /etc/foo/bar
   ```
3. Using [embedded entries](#property-entries):
   ```yaml
   type: htpasswd
   entries: |
     foo:$apr1$zapgfl56$eXIHR/wBYFypkUEXWdCZN/
     bar:$apr1$wqkvo7c2$dqi5g.hK67jLMY4SJzrjq.
   ```

## Compatibility

| <<dist("linux")>> | <<dist("windows")>> |
| - | - |
| <<compatibility_editions(True,True,"linux")>> | <<compatibility_editions(True,None,"windows")>> |
