package task.list.authz

# Positive Tests: Expected to return true
test_allow_with_rgo_test_role_2 {
	input := {
		"authorities": ["RGO_TEST_ROLE_2"]
	}
	allow with input as input
}

test_allow_with_ufo_role_qa {
	input := {
		"authorities": ["UFO_ROLE_QA"]
	}
	allow with input as input
}

test_allow_with_multiple_allowed_roles {
	input := {
		"authorities": ["UFO_ROLE_QA", "RGO_ROLE_ADMIN"]
	}
	allow with input as input
}

test_allow_with_mixture_of_allowed_and_disallowed_roles {
	input := {
		"authorities": ["UFO_ROLE_QA", "DISALLOWED_ROLE"]
	}
	allow with input as input
}

# Negative Tests: Expected to return false
test_disallow_with_no_roles {
	input := {
		"authorities": []
	}
	not allow with input as input
}

test_disallow_with_non_allowed_role {
	input := {
		"authorities": ["NON_ALLOWED_ROLE"]
	}
	not allow with input as input
}

test_disallow_with_multiple_non_allowed_roles {
	input := {
		"authorities": ["NON_ALLOWED_ROLE_1", "NON_ALLOWED_ROLE_2"]
	}
	not allow with input as input
}

test_disallow_with_no_authorities {
	input := {}
	not allow with input as input
}
