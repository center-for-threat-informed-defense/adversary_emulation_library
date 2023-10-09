# Terraform Makefile

The `Makefile` in this directory has two targets, `fmt`, and `docs`.

* The `fmt` target, invoked via `make fmt`, will apply Terraform formatting rules to the Terraform `.tf` files. Only formatting rules will be applied, no functional changes will be made.
* The `docs` target, invoked via `make docs`, uses `terraform-docs`, will update the `scenario/README.md` document to reflect the Terraform codebase.

## References

* [Terraform Formatting](https://developer.hashicorp.com/terraform/cli/commands/fmt)
* [Terraform Docs Tool](https://terraform-docs.io/) (On macOS with Homebrew, installable via `brew install terraform-docs`, see website for other platforms)
* [Infrastructure README](../README.md)
* [Terraform README](./scenario/README.md)
* [Quick Reference](../REFERENCE.md)
