# Rebuilding GCPIAMCustomRolePermissionsConstraint

## Purpose
This repo contains a custom rego policy to check if terraform plan wants to create an invalid custom IAM role in GCP. It can determine whether the new role will contain unlawful permissions, as defined in a constraint definition.

## Setup
The input data has the following schema:

### "constraint": {}
This is the JSON-ified version of the constraint yaml definition. For example, the following:
```
apiVersion: constraints.gatekeeper.sh/v1alpha1
kind: GCPIAMCustomRolePermissionsConstraintV1
metadata:
  name: denylist_custom_role_permissions
  annotations:
    description: Custom IAM roles must never have the following permissions.
spec:
  severity: high
  parameters:
    mode: "denylist"
    title: "Deny highly privileged permissions for custom roles"
    permissions:
      - "bigquery.datasets.get"
      - "bigquery.tables.create"
      - "iam.roles.create"
```
Becomes this when transformed (I used a simple online yaml-json translator):
```
{
    "apiVersion": "constraints.gatekeeper.sh/v1alpha1",
    "kind": "GCPIAMCustomRolePermissionsConstraintV1",
    "metadata": {
        "name": "denylist_custom_role_permissions",
        "annotations": {
            "description": "Custom IAM roles must never have the following permissions."
        }
    },
    "spec": {
        "severity": "high",
        "parameters": {
            "mode": "denylist",
            "title": "Deny highly privileged permissions for custom roles",
            "permissions": [
                "bigquery.datasets.get",
                "bigquery.tables.create",
                "iam.roles.create"
            ]
        }
    }
}
```
### "asset": {}
This is the tfplan json file that gets created when you use `terraform show` on a tfplan resource. I have copied it in verbatim, and the rego policy will search the correct fields.

## Usage:
**I've published a Rego Playground that you can use to play around with the policy [here](https://play.openpolicyagent.org/p/XXthbwaCkY)**

## Methodology:

The policy queries the constraint and the asset for two main sets: what permissions are either allowed or forbidden, and the permissions that terraform intends to create. For the denylist, we look at the intersection between both sets. If there are any overlapping rules, the policy will fail, as terraform plans to create a custom role with a forbidden permission.

"Allow list" takes the difference between asset and constraint permissions. For instance, the roles in the tfplan asset that do NOT appear in the list of allowed permissions.

The rule fails when any matches are found, regardless of operation mode. The matches found, if any, are the matches that violate the constraint permissions.