package terraform.aramco

import input as tfplan
#creates := [res | res:=tfplan.resource_changes[_]; res.change.actions[_] == "create"]

#checking region = me-central2
deny[msg] if {
  tfplan.resource_changes[_].change.after.region != "me-central2"
  msg := "All resources must be in the 'me-central2' region."
}

#checking zone = me-central2-a
deny[msg] if {
  tfplan.resource_changes[_].change.after.zone != "me-central2-a"
  msg := "All resources must be in the 'me-central2-a' zone."
}
