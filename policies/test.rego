package concert.workflows.save.policy_test

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

# test / Rule set 1
deny contains "test / Rule set 1 - No CVE Scan" if {
	some item_1 in object.get(input, "variables", [])
	is_object(item_1)
	item_1["value"] == "scanned"
}
