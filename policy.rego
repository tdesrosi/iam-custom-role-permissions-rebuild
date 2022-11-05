#
# Copyright 2022 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# GCPIAMCustomRolePermissionsConstraintV2 - Raw Rego with Proprietary Input
# Format
#
# What it is: 
# 	Custom rego policy to determine if a terraform plan wants to create an 
#	invalid custom IAM role in GCP. The input data is specified as follows:
#
# There are two main fields: "constraint" and "asset." The constraint is the 
# JSON-ified constraint.yaml that speficies what to look for in the terraform
# plan. The constraint is the entire output of the terraform plan step. We're 
# interested in the array of resource changes where we'll take our constraint 
# and identify any problems with the intended changes. YES, this isn't how it
# is supposed to work in the field, but it's a way to test raw OPA validation 
# vs. the broken state of gcloud terraform vet, where it looks at cloud resource
# manager in the preexisting project or organization node.

package templates.gcp.iam_custom_role_permissions

import input

################
# Check Policy
################

# Check if custom role grants unwanted permissions
deny[{
	"msg": message,
	"details": metadata,
}] {
	# Get constraint body, constraint parameters, and tfplan (asset)
	constraint := input.constraint
	get_constraint_params(constraint, params)
	asset := input.asset

	# Checking for resource changes in tfplan json
	resource_changes := asset.resource_changes[_]

	# Continue if mode = managed and change type is the type we're testing for.
	resource_changes.mode == "managed"
	resource_changes.type == "google_project_iam_custom_role"

	# Permissions are arrays in JSON, we need to make a set.
	asset_permissions := {x | x := resource_changes.change.after.permissions[_]}
	params_permissions := {x | x := config_pattern(params.permissions[_])}

	# Grab title of asset (name of new role, in this case)
	asset_title := get_default(resource_changes, "name", "<NO_RESOURCE_NAME>")

	# Get mode (allowlist or denylist, currently only denylist works)
	mode := get_default(params, "mode", "allowlist")

	# Find violating permissions, depending on the mode of the constraint
	get_violations(mode, asset_permissions, params_permissions, violations_found)

	# With get_violations() we can determine the outliers of both deny and allow modes
	# Deny if there are any violations
	count(violations_found) > 0

	# Give user a message if deny rule is triggered
	message := sprintf("Role %v grants unwanted permission(s): %v", [asset_title, violations_found])
	metadata := {
		"resource_type": resource_changes.type,
		"role_title": asset_title,
		"permissions_in_violation": violations_found,
	}
}

###########################
# Rule Utilities
###########################

# Get violations found, depending on the mode of the constraint
get_violations(mode, asset_permissions, params_permissions) = output {
	# Grab intersect from constraint permissions and tfplan permissions if denylist
	mode == "denylist"
	output = asset_permissions & params_permissions
}

get_violations(mode, asset_permissions, params_permissions) = output {
	# Grab permission(s) that fall outside of allowed permissions list
	# ie. the permissions in tfplan that are not in allowlist
	mode == "allowlist"
	output := asset_permissions - params_permissions
}

# If the member in constraint is written as a single "*", turn it into super
# glob "**". Otherwise, we won't be able to match everything.
config_pattern(old_pattern) = "**" {
	old_pattern == "*"
}

config_pattern(old_pattern) = old_pattern {
	old_pattern != "*"
}

###########################
# Default Lib Utilities
###########################
# These libraries are used for testing in lieu of data.validator.gcp.lib in config validator)

# has_field returns whether an object has a field
has_field(object, field) {
	object[field]
}

# False is a tricky special case, as false responses would create an undefined document unless
# they are explicitly tested for
has_field(object, field) {
	object[field] == false
}

has_field(object, field) = false {
	not object[field]
	not object[field] == false
}

# get_default returns the value of an object's field or the provided default value.
# It avoids creating an undefined state when trying to access an object attribute that does
# not exist
get_default(object, field, _default) = output {
	has_field(object, field)
	output = object[field]
}

get_default(object, field, _default) = output {
	has_field(object, field) == false
	output = _default
}

# Function to fetch the constraint spec
# Usage:
# get_constraint_params(constraint, params)
get_constraint_params(constraint) = params {
	params := constraint.spec.parameters
}
