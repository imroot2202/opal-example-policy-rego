package task.list.authz

default allow = false

allow {
	allowed_roles := {
		"RGO_TEST_ROLE_2",
		"RGO_ROLE_OPERATOR",
		"RGO_ROLE_ADMIN",
		"DEFAULT-ROLES-UFO-KERBEROS",
		"UFO_ROLE_QA",
		"UFO_ROLE_TASKLIST",
		"RGO_ROLE_KYCOPERATOR",
		"RGO_ROLE_KYCSUPERVISOR",
		"RGO_ROLE_KYCCBO",
	}

	user_roles := {role | role := input.authorities[_]}
	user_allowed_roles := user_roles & allowed_roles
	count(user_allowed_roles) > 0
}
