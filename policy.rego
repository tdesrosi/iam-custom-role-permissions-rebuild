# GCPIAMCustomRolePermissionsConstraintV2
#
# Custom rego policy to determine if a terraform plan wants to create an invalid
# custom IAM role in GCP. The input data is specified as follows:
#
# There are two main fields: "constraint" and "asset." The constraint is the 
# JSON-ified constraint.yaml that speficies what to look for in the terraform
# plan. The constraint is the entire output of the terraform plan step. We're 
# interested in the array of resource changes where we'll take our constraint 
# and identify any problems with the intended changes. YES, this isn't how it
# is supposed to work in the field, but it's a way to test raw OPA validation vs.
# the broken state of gcloud terraform vet.

package templates.gcp.iam_custom_role_permissions

import input

################
# Check Policy
################

# Check if custom role grants unwanted permissions
deny[{
	"debug": debug,
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

	# Asset permissions is an array in JSON, we need to make a set.
	asset_permissions := {x | x := resource_changes.change.after.permissions[_]}
	params_permissions := {x | x := config_pattern(params.permissions[_])}

	# Grab title of asset (name of new role, in this case)
	asset_title := resource_changes.name

	# Get mode (allowlist or denylist, currently only denylist works)
	mode := get_default(params, "mode", "allowlist")

	# Grab intersect from constraint permissions and tfplan permissions
	matches_found = asset_permissions & params_permissions

	# Looking for a desired count of 0 (no conflicting deny permissions)
	target_match_count(mode, desired_count)
	count(matches_found) != desired_count

	# Debug statement to show which permission(s) caused the deny ruling
	debug := sprintf("matches_found %v", [matches_found])

	# Give user a message
	message := sprintf("Role %v grants permission %v", [asset_title, matches_found])
	metadata := {
		"resource": resource_changes.type,
		"role_title": asset_title,
		"permission": asset_permissions,
	}
}

###########################
# Rule Utilities
###########################

# Determine the overlap between matches under test and constraint
target_match_count(mode) = 0 {
	mode == "denylist"
}

target_match_count(mode) = 1 {
	mode == "allowlist"
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
