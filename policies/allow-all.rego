package concert.workflows.run.policy_allow_all

import rego.v1

deny contains reason if {
	false
	reason := ""
}

review contains reason if {
	false
	reason := ""
}

deny_reasons := [reason | deny[reason]]

review_reasons := [reason | review[reason]]

default decision := {
	"outcome": "review",
	"reasons": ["Policy decision could not be evaluated"],
}

decision := {
	"outcome": "allow",
	"reasons": [],
} if {
	count(deny_reasons) == 0
	count(review_reasons) == 0
}

decision := {
	"outcome": "review",
	"reasons": sort(review_reasons),
} if {
	count(deny_reasons) == 0
	count(review_reasons) > 0
}

decision := {
	"outcome": "deny",
	"reasons": sort(deny_reasons),
} if {
	count(deny_reasons) > 0
}

# allow all / Rule set 1
review contains "allow all / Rule set 1 - ruleset 1 test" if {
	count({item_1 |
	some item_1 in object.get(input, "variables", [])
	is_object(item_1)
	value_1_1 := object.get(item_1, "name", null)
	value_1_1 == null
	}) == 0
}
