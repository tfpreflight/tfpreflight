package dependencies

// assignedIDs are resource types whose Terraform id is an opaque id that AWS
// picks when the resource is created. The pack builder could not tell this
// for them and marked their identity unknown, which made every check of a
// literal id against such a type PARTIAL as soon as the same plan created
// one. No literal in a configuration can equal an id that does not exist yet,
// so for these types a planned create is never the thing the literal names.
//
// Each type was read in the provider's source at v6.64.0: the create handler
// calls d.SetId with a field of the Create response, and that field is an id,
// not a name the caller chose. Types whose id is a name or an ARN are left out
// on purpose: a literal can be written to equal those.
var assignedIDs = map[string]bool{
	"aws_security_group":              true, // ec2/vpc_security_group.go:215, CreateSecurityGroup GroupId
	"aws_ec2_transit_gateway":         true, // ec2/transitgateway_.go:198, CreateTransitGateway TransitGatewayId
	"aws_directory_service_directory": true, // ds/directory.go:510, 549, 591, DirectoryId of the three directory creates
	"aws_ebs_snapshot":                true, // ec2/ebs_snapshot.go:144, CreateSnapshot SnapshotId
	"aws_network_interface":           true, // ec2/vpc_network_interface.go:480, CreateNetworkInterface NetworkInterfaceId
	"aws_instance":                    true, // ec2/ec2_instance.go:1225-1226, RunInstances Instances[0].InstanceId
	"aws_efs_file_system":             true, // efs/file_system.go:235, CreateFileSystem FileSystemId
	"aws_prometheus_workspace":        true, // amp/workspace.go:121, CreateWorkspace WorkspaceId
	"aws_transfer_server":             true, // transfer/server.go:464, CreateServer ServerId
	"aws_vpc_endpoint_service":        true, // ec2/vpc_endpoint_service.go:200, CreateVpcEndpointServiceConfiguration ServiceId
	"aws_sagemaker_domain":            true, // sagemaker/domain.go:1553-1554, CreateDomain DomainId
	"aws_ec2_traffic_mirror_filter":   true, // ec2/vpc_traffic_mirror_filter.go:91, CreateTrafficMirrorFilter TrafficMirrorFilterId
	"aws_ssm_maintenance_window":      true, // ssm/maintenance_window.go:135, CreateMaintenanceWindow WindowId
	"aws_servicecatalog_tag_option":   true, // servicecatalog/tag_option.go:101, CreateTagOption TagOptionDetail.Id
	"aws_vpc_ipam_resource_discovery": true, // ec2/vpc_ipam_resource_discovery.go:142, CreateIpamResourceDiscovery IpamResourceDiscoveryId
}

// targetIdentity is where the rule's target id comes from. It is the pack's
// answer, except that an unknown id of a type in assignedIDs is server-generated.
// It only lets the check rule out a same-plan create, so it never makes a
// finding block.
func targetIdentity(rule ExistenceRule) string {
	if (rule.TargetIdentity == IdentityUnknown || rule.TargetIdentity == "") && rule.TargetAttribute == "id" && assignedIDs[rule.TargetResource] {
		return IdentityServerGenerated
	}
	return rule.TargetIdentity
}
