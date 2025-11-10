from botocore.exceptions import ClientError
from scanner.mitre_maps.ec2_mitre_map import EC2Vulnerability
from scanner.utils import new_vulnerability
from scanner.aws.decorator import inject_clients


@inject_clients(clients=["ec2"])
def find_security_groups_open_ingress(ec2_client, findings):
    response = ec2_client.describe_security_groups()
    for sg in response.get("SecurityGroups", []):
        sg_name = sg.get("GroupName") or sg.get("GroupId")
        for perm in sg.get("IpPermissions", []):
            for ip_range in perm.get("IpRanges", []):
                if ip_range.get("CidrIp") == "0.0.0.0/0":
                    findings.append(
                        new_vulnerability(
                            EC2Vulnerability.open_security_group_ingress,
                            sg_name,
                            "ec2",
                        )
                    )
                    break
            for ip_range in perm.get("Ipv6Ranges", []):
                if ip_range.get("CidrIpv6") == "::/0":
                    findings.append(
                        new_vulnerability(
                            EC2Vulnerability.open_security_group_ingress,
                            sg_name,
                            "ec2",
                        )
                    )
                    break


@inject_clients(clients=["ec2"])
def find_security_groups_open_egress(ec2_client, findings):
    response = ec2_client.describe_security_groups()
    for sg in response.get("SecurityGroups", []):
        sg_name = sg.get("GroupName") or sg.get("GroupId")
        for perm in sg.get("IpPermissionsEgress", []):
            for ip_range in perm.get("IpRanges", []):
                if ip_range.get("CidrIp") == "0.0.0.0/0":
                    findings.append(
                        new_vulnerability(
                            EC2Vulnerability.open_security_group_egress,
                            sg_name,
                            "ec2",
                        )
                    )
                    break
            for ip_range in perm.get("Ipv6Ranges", []):
                if ip_range.get("CidrIpv6") == "::/0":
                    findings.append(
                        new_vulnerability(
                            EC2Vulnerability.open_security_group_egress,
                            sg_name,
                            "ec2",
                        )
                    )
                    break


@inject_clients(clients=["ec2"])
def find_unused_security_groups(ec2_client, findings):
    all_sgs = ec2_client.describe_security_groups().get("SecurityGroups", [])
    all_enis = ec2_client.describe_network_interfaces().get("NetworkInterfaces", [])
    used_sg_ids = set()
    for eni in all_enis:
        for sg in eni.get("Groups", []):
            used_sg_ids.add(sg.get("GroupId"))
    for sg in all_sgs:
        sg_id = sg.get("GroupId")
        if sg_id not in used_sg_ids:
            findings.append(
                new_vulnerability(EC2Vulnerability.unused_security_group, sg_id, "ec2")
            )


@inject_clients(clients=["ec2"])
def find_vpc_flow_logs_disabled(ec2_client, findings):
    vpcs_resp = ec2_client.describe_vpcs()
    for vpc in vpcs_resp.get("Vpcs", []):
        vpc_id = vpc.get("VpcId")
        flow_logs_resp = ec2_client.describe_flow_logs(
            Filters=[{"Name": "resource-id", "Values": [vpc_id]}]
        )
        if not flow_logs_resp.get("FlowLogs"):
            findings.append(
                new_vulnerability(
                    EC2Vulnerability.vpc_flow_logs_disabled, vpc_id, "ec2"
                )
            )


@inject_clients(clients=["ec2"])
def find_ebs_unencrypted(ec2_client, findings):
    volumes = ec2_client.describe_volumes().get("Volumes", [])
    for vol in volumes:
        if not vol.get("Encrypted", False):
            findings.append(
                new_vulnerability(
                    EC2Vulnerability.ebs_volume_unencrypted, vol["VolumeId"], "ec2"
                )
            )


@inject_clients(clients=["ec2"])
def find_ec2_instance_public_ip(ec2_client, findings):
    reservations = ec2_client.describe_instances().get("Reservations", [])
    for reservation in reservations:
        for instance in reservation.get("Instances", []):
            if instance.get("PublicIpAddress"):
                findings.append(
                    new_vulnerability(
                        EC2Vulnerability.ec2_instance_public_ip,
                        instance.get("InstanceId"),
                        "ec2",
                    )
                )


@inject_clients(clients=["ec2"])
def find_security_groups_with_ssh_open(ec2_client, findings):
    response = ec2_client.describe_security_groups()
    for sg in response.get("SecurityGroups", []):
        sg_name = sg.get("GroupName") or sg.get("GroupId")
        for perm in sg.get("IpPermissions", []):
            if perm.get("FromPort") == 22 or perm.get("ToPort") == 22:
                for ip_range in perm.get("IpRanges", []):
                    if ip_range.get("CidrIp") == "0.0.0.0/0":
                        findings.append(
                            new_vulnerability(
                                EC2Vulnerability.sg_ssh_open, sg_name, "ec2"
                            )
                        )
                        break


@inject_clients(clients=["ec2"])
def find_security_groups_with_rdp_open(ec2_client, findings):
    response = ec2_client.describe_security_groups()
    for sg in response.get("SecurityGroups", []):
        sg_name = sg.get("GroupName") or sg.get("GroupId")
        for perm in sg.get("IpPermissions", []):
            if perm.get("FromPort") == 3389 or perm.get("ToPort") == 3389:
                for ip_range in perm.get("IpRanges", []):
                    if ip_range.get("CidrIp") == "0.0.0.0/0":
                        findings.append(
                            new_vulnerability(
                                EC2Vulnerability.sg_rdp_open, sg_name, "ec2"
                            )
                        )
                        break


@inject_clients(clients=["ec2"])
def find_default_vpc_in_use(ec2_client, findings):
    vpcs = ec2_client.describe_vpcs(Filters=[{"Name": "isDefault", "Values": ["true"]}])
    for vpc in vpcs.get("Vpcs", []):
        instances = ec2_client.describe_instances(
            Filters=[{"Name": "vpc-id", "Values": [vpc.get("VpcId")]}]
        )
        if instances.get("Reservations"):
            findings.append(
                new_vulnerability(
                    EC2Vulnerability.default_vpc_in_use, vpc.get("VpcId"), "ec2"
                )
            )


@inject_clients(clients=["ec2"])
def find_default_security_group_in_use(ec2_client, findings):
    response = ec2_client.describe_security_groups(
        Filters=[{"Name": "group-name", "Values": ["default"]}]
    )
    for sg in response.get("SecurityGroups", []):
        vpc_id = sg.get("VpcId")
        if sg.get("IpPermissions") or sg.get("IpPermissionsEgress"):
            findings.append(
                new_vulnerability(EC2Vulnerability.default_sg_in_use, vpc_id, "ec2")
            )


@inject_clients(clients=["ec2"])
def find_instances_without_monitoring(ec2_client, findings):
    reservations = ec2_client.describe_instances().get("Reservations", [])
    for reservation in reservations:
        for instance in reservation.get("Instances", []):
            if not instance.get("Monitoring", {}).get("State") == "enabled":
                findings.append(
                    new_vulnerability(
                        EC2Vulnerability.detailed_monitoring_disabled,
                        instance.get("InstanceId"),
                        "ec2",
                    )
                )


@inject_clients(clients=["ec2"])
def find_ebs_optimization_disabled(ec2_client, findings):
    reservations = ec2_client.describe_instances().get("Reservations", [])
    for reservation in reservations:
        for instance in reservation.get("Instances", []):
            if instance.get("State", {}).get("Name") == "running":
                if not instance.get("EbsOptimized", False):
                    findings.append(
                        new_vulnerability(
                            EC2Vulnerability.ebs_optimization_disabled,
                            instance.get("InstanceId"),
                            "ec2",
                        )
                    )


@inject_clients(clients=["ec2"])
def find_termination_protection_disabled(ec2_client, findings):
    reservations = ec2_client.describe_instances().get("Reservations", [])
    for reservation in reservations:
        for instance in reservation.get("Instances", []):
            instance_id = instance.get("InstanceId")
            try:
                attr = ec2_client.describe_instance_attribute(
                    InstanceId=instance_id, Attribute="disableApiTermination"
                )
                if not attr.get("DisableApiTermination", {}).get("Value", False):
                    findings.append(
                        new_vulnerability(
                            EC2Vulnerability.termination_protection_disabled,
                            instance_id,
                            "ec2",
                        )
                    )
            except ClientError:
                continue


@inject_clients(clients=["ec2"])
def find_unattached_elastic_ips(ec2_client, findings):
    response = ec2_client.describe_addresses()
    for addr in response.get("Addresses", []):
        if not addr.get("InstanceId"):
            findings.append(
                new_vulnerability(
                    EC2Vulnerability.unattached_eip, addr.get("PublicIp"), "ec2"
                )
            )


@inject_clients(clients=["ec2"])
def find_instances_with_public_eni(ec2_client, findings):
    reservations = ec2_client.describe_instances().get("Reservations", [])
    for reservation in reservations:
        for instance in reservation.get("Instances", []):
            for eni in instance.get("NetworkInterfaces", []):
                if eni.get("Association", {}).get("PublicIp"):
                    findings.append(
                        new_vulnerability(
                            EC2Vulnerability.instance_public_eni,
                            instance.get("InstanceId"),
                            "ec2",
                        )
                    )
                    break


@inject_clients(clients=["ec2"])
def find_volumes_without_snapshots(ec2_client, findings):
    volumes = ec2_client.describe_volumes().get("Volumes", [])
    for vol in volumes:
        snapshots = ec2_client.describe_snapshots(
            Filters=[{"Name": "volume-id", "Values": [vol["VolumeId"]]}]
        )
        if not snapshots.get("Snapshots"):
            findings.append(
                new_vulnerability(EC2Vulnerability.no_snapshots, vol["VolumeId"], "ec2")
            )


@inject_clients(clients=["ec2"])
def find_unencrypted_snapshots(ec2_client, findings):
    snapshots = ec2_client.describe_snapshots(OwnerIds=["self"]).get("Snapshots", [])
    for snapshot in snapshots:
        if not snapshot.get("Encrypted", False):
            findings.append(
                new_vulnerability(
                    EC2Vulnerability.unencrypted_snapshot,
                    snapshot.get("SnapshotId"),
                    "ec2",
                )
            )


@inject_clients(clients=["ec2"])
def find_public_snapshots(ec2_client, findings):
    snapshots = ec2_client.describe_snapshots(OwnerIds=["self"]).get("Snapshots", [])
    for snapshot in snapshots:
        if snapshot.get("Public", False):
            findings.append(
                new_vulnerability(
                    EC2Vulnerability.public_snapshot,
                    snapshot.get("SnapshotId"),
                    "ec2",
                )
            )


@inject_clients(clients=["ec2"])
def find_public_amis(ec2_client, findings):
    images = ec2_client.describe_images(Owners=["self"]).get("Images", [])
    for image in images:
        if image.get("Public", False):
            findings.append(
                new_vulnerability(
                    EC2Vulnerability.public_ami, image.get("ImageId"), "ec2"
                )
            )


@inject_clients(clients=["ec2"])
def find_unencrypted_ebs_snapshots(ec2_client, findings):
    snapshots = ec2_client.describe_snapshots(OwnerIds=["self"]).get("Snapshots", [])
    for snapshot in snapshots:
        if not snapshot.get("Encrypted", False):
            findings.append(
                new_vulnerability(
                    EC2Vulnerability.unencrypted_snapshot,
                    snapshot.get("SnapshotId"),
                    "ec2",
                )
            )


@inject_clients(clients=["ec2"])
def find_network_acls_allowing_all_traffic(ec2_client, findings):
    nacls = ec2_client.describe_network_acls().get("NetworkAcls", [])
    for nacl in nacls:
        for entry in nacl.get("Entries", []):
            if (
                entry.get("CidrBlock") == "0.0.0.0/0"
                and entry.get("RuleAction") == "allow"
            ):
                findings.append(
                    new_vulnerability(
                        EC2Vulnerability.nacl_allow_all,
                        nacl.get("NetworkAclId"),
                        "ec2",
                    )
                )
                break


@inject_clients(clients=["ec2"])
def find_route_tables_with_overly_permissive_routes(ec2_client, findings):
    route_tables = ec2_client.describe_route_tables().get("RouteTables", [])
    for rt in route_tables:
        for route in rt.get("Routes", []):
            if route.get("DestinationCidrBlock") == "0.0.0.0/0":
                findings.append(
                    new_vulnerability(
                        EC2Vulnerability.route_table_open,
                        rt.get("RouteTableId"),
                        "ec2",
                    )
                )
                break


@inject_clients(clients=["ec2"])
def find_nat_gateways_without_eip(ec2_client, findings):
    nat_gateways = ec2_client.describe_nat_gateways().get("NatGateways", [])
    for nat in nat_gateways:
        if not nat.get("NatGatewayAddresses", [{}])[0].get("PublicIp"):
            findings.append(
                new_vulnerability(
                    EC2Vulnerability.nat_gateway_no_eip,
                    nat.get("NatGatewayId"),
                    "ec2",
                )
            )


@inject_clients(clients=["ec2"])
def find_vpn_connections_not_encrypted(ec2_client, findings):
    vpns = ec2_client.describe_vpn_connections().get("VpnConnections", [])
    for vpn in vpns:
        options = vpn.get("Options", {})
        if not options.get("TunnelEncryption", False):
            findings.append(
                new_vulnerability(
                    EC2Vulnerability.vpn_not_encrypted,
                    vpn.get("VpnConnectionId"),
                    "ec2",
                )
            )


@inject_clients(clients=["ec2"])
def find_vpn_connections_not_authenticated(ec2_client, findings):
    vpns = ec2_client.describe_vpn_connections().get("VpnConnections", [])
    for vpn in vpns:
        options = vpn.get("Options", {})
        if options.get("ReplayWindowSize", 0) == 0:
            findings.append(
                new_vulnerability(
                    EC2Vulnerability.vpn_not_authenticated,
                    vpn.get("VpnConnectionId"),
                    "ec2",
                )
            )


@inject_clients(clients=["ec2"])
def find_instances_without_ebs_delete_on_termination(ec2_client, findings):
    reservations = ec2_client.describe_instances().get("Reservations", [])
    for reservation in reservations:
        for instance in reservation.get("Instances", []):
            instance_id = instance.get("InstanceId")
            for block_device in instance.get("BlockDeviceMappings", []):
                if not block_device.get("Ebs", {}).get("DeleteOnTermination", False):
                    findings.append(
                        new_vulnerability(
                            EC2Vulnerability.ebs_delete_on_termination_disabled,
                            instance_id,
                            "ec2",
                        )
                    )
                    break


@inject_clients(clients=["ec2"])
def find_instances_without_iam_instance_profile(ec2_client, findings):
    reservations = ec2_client.describe_instances().get("Reservations", [])
    for reservation in reservations:
        for instance in reservation.get("Instances", []):
            if not instance.get("IamInstanceProfile"):
                findings.append(
                    new_vulnerability(
                        EC2Vulnerability.instance_no_iam_profile,
                        instance.get("InstanceId"),
                        "ec2",
                    )
                )


@inject_clients(clients=["ec2"])
def find_instances_without_source_destination_check(ec2_client, findings):
    reservations = ec2_client.describe_instances().get("Reservations", [])
    for reservation in reservations:
        for instance in reservation.get("Instances", []):
            for eni in instance.get("NetworkInterfaces", []):
                if eni.get("SourceDestCheck", True):
                    findings.append(
                        new_vulnerability(
                            EC2Vulnerability.source_dest_check_enabled,
                            instance.get("InstanceId"),
                            "ec2",
                        )
                    )
                    break


@inject_clients(clients=["ec2"])
def find_key_pairs_without_tags(ec2_client, findings):
    key_pairs = ec2_client.describe_key_pairs().get("KeyPairs", [])
    for key in key_pairs:
        if not key.get("Tags"):
            findings.append(
                new_vulnerability(
                    EC2Vulnerability.key_pair_no_tags, key.get("KeyName"), "ec2"
                )
            )


@inject_clients(clients=["ec2"])
def find_security_groups_without_description(ec2_client, findings):
    response = ec2_client.describe_security_groups()
    for sg in response.get("SecurityGroups", []):
        if not sg.get("GroupDescription"):
            findings.append(
                new_vulnerability(
                    EC2Vulnerability.sg_no_description, sg.get("GroupId"), "ec2"
                )
            )


@inject_clients(clients=["ec2"])
def find_instances_with_default_tenancy(ec2_client, findings):
    reservations = ec2_client.describe_instances().get("Reservations", [])
    for reservation in reservations:
        for instance in reservation.get("Instances", []):
            if instance.get("Tenancy") == "default":
                findings.append(
                    new_vulnerability(
                        EC2Vulnerability.instance_default_tenancy,
                        instance.get("InstanceId"),
                        "ec2",
                    )
                )


@inject_clients(clients=["ec2"])
def find_instances_without_shutdown_behavior_stop(ec2_client, findings):
    reservations = ec2_client.describe_instances().get("Reservations", [])
    for reservation in reservations:
        for instance in reservation.get("Instances", []):
            instance_id = instance.get("InstanceId")
            try:
                attr = ec2_client.describe_instance_attribute(
                    InstanceId=instance_id,
                    Attribute="instanceInitiatedShutdownBehavior",
                )
                if (
                    attr.get("InstanceInitiatedShutdownBehavior", {}).get("Value")
                    != "stop"
                ):
                    findings.append(
                        new_vulnerability(
                            EC2Vulnerability.instance_shutdown_behavior,
                            instance_id,
                            "ec2",
                        )
                    )
            except ClientError:
                continue
