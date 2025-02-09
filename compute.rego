package terraform.ar.compute

import input.plan as plan

# Allowed compute types
allowed_compute_types := {"n1-standard-1", "n2-standard-2"}

# Rule to deny if an invalid compute type is detected
deny[msg] {
    # Extract each resource from the Terraform plan
    resource := plan.resource_changes[_]

    # Check if the resource is a Google Compute Instance
    resource.type == "google_compute_instance"
    
    # Extract the machine type
    machine_type := resource.change.after.machine_type

    # Validate the machine type
    not allowed_compute_types[machine_type]
    
    msg := sprintf("Resource '%s' has an invalid machine type: '%s'. Allowed machine types are: %v.",[resource.name, machine_type, allowed_compute_types])
}
