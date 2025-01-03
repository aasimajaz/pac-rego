package terraform.ar.compute

#import input as tfplan
#creates := [res | res:=tfplan.resource_changes[_]; res.change.actions[_] == "create"]


# Allowed compute types
allowed_compute_types = {"n1-standard-1", "n2-standard-2"}


# Rule to deny if an invalid compute type is detected
deny[msg] if{
    # Extract each resource from the Terraform plan
    resource := input.resource_changes[_]

    # Check if the resource is a Google Compute Instance
    resource.type == "google_compute_instance"

    # Extract the machine type
    machine_type := resource.change.after.machine_type
    #enable print to see machine_type detected
    # print(machine_type)

    # Validate the machine type
    not machine_type in allowed_compute_types

    # Return the denial message
    msg := sprintf(
        "Resource '%s' has an invalid machine type: '%s'. Allowed machine types are: %v.",
        [resource.name, machine_type, allowed_compute_types]
    )
}

