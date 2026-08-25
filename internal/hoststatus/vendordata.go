package hoststatus

// Vendordata states, as filed in capability details.
//
// This vocabulary is part of the probe contract, not of any one probe: the
// vendordata probe writes it, the fleet assessment folds on it, and the farm
// screen renders it. It lived in probes, which made the assessment import the
// collector package — and everything the collectors need, config included —
// for four strings.
// Vendordata states, as filed in capability details.
const (
	// VendordataOn — the serving service is configured and the file it names is
	// there. New VMs get the cloud-config.
	VendordataOn = "on"
	// VendordataOff — neither. The farm has never been onboarded.
	VendordataOff = "off"
	// VendordataNoFile — the config names a file that is not there.
	//
	// Worse than off. Kolla declares the mount as non-optional, so
	// kolla_set_configs raises MissingRequiredSource and the container will not
	// start the next time anything restarts it. Measured on kolla-ansible
	// 20.2.0, which declares the mount for nova-metadata but only ever copies
	// the file to nova-api.
	VendordataNoFile = "config-without-file"
	// VendordataNoConfig — the file is there and nothing reads it.
	//
	// This is what a month of silent failure looks like from the host: somebody
	// put the file in place, the service that answers metadata was never told
	// about it, and the only symptom is an empty vendor_data.json.
	VendordataNoConfig = "file-without-config"
)
