from botocore.exceptions import ClientError
from scanner.mitre_maps.ec2_mitre_map import EC2Vulnerability
from scanner.utils import new_vulnerability
from scanner.aws.decorator import inject_clients
from concurrent.futures import ThreadPoolExecutor
import logging

logger = logging.getLogger(__name__)


def fetch_security_groups(ec2_client):
    """Fetch all security groups once for reuse across checks"""
    try:
        return ec2_client.describe_security_groups().get("SecurityGroups", [])
    except Exception as e:
        logger.error(f"Error fetching security groups: {e}")
        return []


def fetch_instances(ec2_client):
    """Fetch all instances once for reuse across checks"""
    try:
        instances = []
        reservations = ec2_client.describe_instances().get("Reservations", [])
        for reservation in reservations:
            instances.extend(reservation.get("Instances", []))
        return instances
    except Exception as e:
        logger.error(f"Error fetching instances: {e}")
        return []


def fetch_volumes(ec2_client):
    """Fetch all volumes once for reuse across checks"""
    try:
        return ec2_client.describe_volumes().get("Volumes", [])
    except Exception as e:
        logger.error(f"Error fetching volumes: {e}")
        return []


def fetch_snapshots(ec2_client):
    """Fetch all snapshots once for reuse across checks"""
    try:
        return ec2_client.describe_snapshots(OwnerIds=["self"]).get("Snapshots", [])
    except Exception as e:
        logger.error(f"Error fetching snapshots: {e}")
        return []


@inject_clients(clients=["ec2"])
def find_security_groups_open_ingress(ec2_client, findings, security_groups=None):
    if security_groups is None:
        security_groups = fetch_security_groups(ec2_client)

    def check_open_ingress(sg):
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
                    return
            for ip_range in perm.get("Ipv6Ranges", []):
                if ip_range.get("CidrIpv6") == "::/0":
                    findings.append(
                        new_vulnerability(
                            EC2Vulnerability.open_security_group_ingress,
                            sg_name,
                            "ec2",
                        )
                    )
                    return

    with ThreadPoolExecutor(max_workers=8) as executor:
        executor.map(check_open_ingress, security_groups)


@inject_clients(clients=["ec2"])
def find_security_groups_open_egress(ec2_client, findings, security_groups=None):
    if security_groups is None:
        security_groups = fetch_security_groups(ec2_client)

    def check_open_egress(sg):
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
                    return
            for ip_range in perm.get("Ipv6Ranges", []):
                if ip_range.get("CidrIpv6") == "::/0":
                    findings.append(
                        new_vulnerability(
                            EC2Vulnerability.open_security_group_egress,
                            sg_name,
                            "ec2",
                        )
                    )
                    return

    with ThreadPoolExecutor(max_workers=8) as executor:
        executor.map(check_open_egress, security_groups)


@inject_clients(clients=["ec2"])
def find_unused_security_groups(ec2_client, findings):
    all_sgs = fetch_security_groups(ec2_client)
    try:
        all_enis = ec2_client.describe_network_interfaces().get("NetworkInterfaces", [])
    except Exception as e:
        logger.error(f"Error fetching ENIs: {e}")
        return

    used_sg_ids = set()
    for eni in all_enis:
        for sg in eni.get("Groups", []):
            used_sg_ids.add(sg.get("GroupId"))

    def check_unused(sg):
        sg_id = sg.get("GroupId")
        if sg_id not in used_sg_ids:
            findings.append(
                new_vulnerability(EC2Vulnerability.unused_security_group, sg_id, "ec2")
            )

    with ThreadPoolExecutor(max_workers=8) as executor:
        executor.map(check_unused, all_sgs)


@inject_clients(clients=["ec2"])
def find_vpc_flow_logs_disabled(ec2_client, findings):
    try:
        vpcs = ec2_client.describe_vpcs().get("Vpcs", [])
    except Exception as e:
        logger.error(f"Error fetching VPCs: {e}")
        return

    def check_flow_logs(vpc):
        vpc_id = vpc.get("VpcId")
        try:
            flow_logs_resp = ec2_client.describe_flow_logs(
                Filters=[{"Name": "resource-id", "Values": [vpc_id]}]
            )
            if not flow_logs_resp.get("FlowLogs"):
                findings.append(
                    new_vulnerability(
                        EC2Vulnerability.vpc_flow_logs_disabled, vpc_id, "ec2"
                    )
                )
        except ClientError:
            pass

    with ThreadPoolExecutor(max_workers=8) as executor:
        executor.map(check_flow_logs, vpcs)


@inject_clients(clients=["ec2"])
def find_ebs_unencrypted(ec2_client, findings, volumes=None):
    if volumes is None:
        volumes = fetch_volumes(ec2_client)

    def check_encryption(vol):
        if not vol.get("Encrypted", False):
            findings.append(
                new_vulnerability(
                    EC2Vulnerability.ebs_volume_unencrypted, vol["VolumeId"], "ec2"
                )
            )

    with ThreadPoolExecutor(max_workers=8) as executor:
        executor.map(check_encryption, volumes)


@inject_clients(clients=["ec2"])
def find_ec2_instance_public_ip(ec2_client, findings, instances=None):
    if instances is None:
        instances = fetch_instances(ec2_client)

    def check_public_ip(instance):
        if instance.get("PublicIpAddress"):
            findings.append(
                new_vulnerability(
                    EC2Vulnerability.ec2_instance_public_ip,
                    instance.get("InstanceId"),
                    "ec2",
                )
            )

    with ThreadPoolExecutor(max_workers=8) as executor:
        executor.map(check_public_ip, instances)


@inject_clients(clients=["ec2"])
def find_security_groups_with_ssh_open(ec2_client, findings, security_groups=None):
    if security_groups is None:
        security_groups = fetch_security_groups(ec2_client)

    def check_ssh_open(sg):
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
                        return

    with ThreadPoolExecutor(max_workers=8) as executor:
        executor.map(check_ssh_open, security_groups)


@inject_clients(clients=["ec2"])
def find_security_groups_with_rdp_open(ec2_client, findings, security_groups=None):
    if security_groups is None:
        security_groups = fetch_security_groups(ec2_client)

    def check_rdp_open(sg):
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
                        return

    with ThreadPoolExecutor(max_workers=8) as executor:
        executor.map(check_rdp_open, security_groups)


@inject_clients(clients=["ec2"])
def find_default_vpc_in_use(ec2_client, findings):
    try:
        vpcs = ec2_client.describe_vpcs(
            Filters=[{"Name": "isDefault", "Values": ["true"]}]
        ).get("Vpcs", [])
    except Exception as e:
        logger.error(f"Error fetching default VPCs: {e}")
        return

    def check_vpc_usage(vpc):
        vpc_id = vpc.get("VpcId")
        try:
            instances = ec2_client.describe_instances(
                Filters=[{"Name": "vpc-id", "Values": [vpc_id]}]
            )
            if instances.get("Reservations"):
                findings.append(
                    new_vulnerability(
                        EC2Vulnerability.default_vpc_in_use, vpc_id, "ec2"
                    )
                )
        except ClientError:
            pass

    with ThreadPoolExecutor(max_workers=8) as executor:
        executor.map(check_vpc_usage, vpcs)


@inject_clients(clients=["ec2"])
def find_default_security_group_in_use(ec2_client, findings):
    try:
        response = ec2_client.describe_security_groups(
            Filters=[{"Name": "group-name", "Values": ["default"]}]
        )
        default_sgs = response.get("SecurityGroups", [])
    except Exception as e:
        logger.error(f"Error fetching default security groups: {e}")
        return

    def check_sg_in_use(sg):
        vpc_id = sg.get("VpcId")
        if sg.get("IpPermissions") or sg.get("IpPermissionsEgress"):
            findings.append(
                new_vulnerability(EC2Vulnerability.default_sg_in_use, vpc_id, "ec2")
            )

    with ThreadPoolExecutor(max_workers=8) as executor:
        executor.map(check_sg_in_use, default_sgs)


@inject_clients(clients=["ec2"])
def find_instances_without_monitoring(ec2_client, findings, instances=None):
    if instances is None:
        instances = fetch_instances(ec2_client)

    def check_monitoring(instance):
        if not instance.get("Monitoring", {}).get("State") == "enabled":
            findings.append(
                new_vulnerability(
                    EC2Vulnerability.detailed_monitoring_disabled,
                    instance.get("InstanceId"),
                    "ec2",
                )
            )

    with ThreadPoolExecutor(max_workers=8) as executor:
        executor.map(check_monitoring, instances)


@inject_clients(clients=["ec2"])
def find_ebs_optimization_disabled(ec2_client, findings, instances=None):
    if instances is None:
        instances = fetch_instances(ec2_client)

    def check_ebs_optimization(instance):
        if instance.get("State", {}).get("Name") == "running":
            if not instance.get("EbsOptimized", False):
                findings.append(
                    new_vulnerability(
                        EC2Vulnerability.ebs_optimization_disabled,
                        instance.get("InstanceId"),
                        "ec2",
                    )
                )

    with ThreadPoolExecutor(max_workers=8) as executor:
        executor.map(check_ebs_optimization, instances)


@inject_clients(clients=["ec2"])
def find_termination_protection_disabled(ec2_client, findings, instances=None):
    if instances is None:
        instances = fetch_instances(ec2_client)

    def check_termination_protection(instance):
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
            pass

    with ThreadPoolExecutor(max_workers=8) as executor:
        executor.map(check_termination_protection, instances)


@inject_clients(clients=["ec2"])
def find_unattached_elastic_ips(ec2_client, findings):
    try:
        response = ec2_client.describe_addresses()
        addresses = response.get("Addresses", [])
    except Exception as e:
        logger.error(f"Error fetching elastic IPs: {e}")
        return

    def check_unattached(addr):
        if not addr.get("InstanceId"):
            findings.append(
                new_vulnerability(
                    EC2Vulnerability.unattached_eip, addr.get("PublicIp"), "ec2"
                )
            )

    with ThreadPoolExecutor(max_workers=8) as executor:
        executor.map(check_unattached, addresses)


@inject_clients(clients=["ec2"])
def find_instances_with_public_eni(ec2_client, findings, instances=None):
    if instances is None:
        instances = fetch_instances(ec2_client)

    def check_public_eni(instance):
        for eni in instance.get("NetworkInterfaces", []):
            if eni.get("Association", {}).get("PublicIp"):
                findings.append(
                    new_vulnerability(
                        EC2Vulnerability.instance_public_eni,
                        instance.get("InstanceId"),
                        "ec2",
                    )
                )
                return

    with ThreadPoolExecutor(max_workers=8) as executor:
        executor.map(check_public_eni, instances)


@inject_clients(clients=["ec2"])
def find_volumes_without_snapshots(ec2_client, findings, volumes=None):
    if volumes is None:
        volumes = fetch_volumes(ec2_client)

    def check_snapshots(vol):
        try:
            snapshots = ec2_client.describe_snapshots(
                Filters=[{"Name": "volume-id", "Values": [vol["VolumeId"]]}]
            )
            if not snapshots.get("Snapshots"):
                findings.append(
                    new_vulnerability(
                        EC2Vulnerability.no_snapshots, vol["VolumeId"], "ec2"
                    )
                )
        except ClientError:
            pass

    with ThreadPoolExecutor(max_workers=8) as executor:
        executor.map(check_snapshots, volumes)


@inject_clients(clients=["ec2"])
def find_unencrypted_snapshots(ec2_client, findings, snapshots=None):
    if snapshots is None:
        snapshots = fetch_snapshots(ec2_client)

    def check_encryption(snapshot):
        if not snapshot.get("Encrypted", False):
            findings.append(
                new_vulnerability(
                    EC2Vulnerability.unencrypted_snapshot,
                    snapshot.get("SnapshotId"),
                    "ec2",
                )
            )

    with ThreadPoolExecutor(max_workers=8) as executor:
        executor.map(check_encryption, snapshots)


@inject_clients(clients=["ec2"])
def find_public_snapshots(ec2_client, findings, snapshots=None):
    if snapshots is None:
        snapshots = fetch_snapshots(ec2_client)

    def check_public(snapshot):
        if snapshot.get("Public", False):
            findings.append(
                new_vulnerability(
                    EC2Vulnerability.public_snapshot,
                    snapshot.get("SnapshotId"),
                    "ec2",
                )
            )

    with ThreadPoolExecutor(max_workers=8) as executor:
        executor.map(check_public, snapshots)


@inject_clients(clients=["ec2"])
def find_public_amis(ec2_client, findings):
    try:
        images = ec2_client.describe_images(Owners=["self"]).get("Images", [])
    except Exception as e:
        logger.error(f"Error fetching AMIs: {e}")
        return

    def check_public_ami(image):
        if image.get("Public", False):
            findings.append(
                new_vulnerability(
                    EC2Vulnerability.public_ami, image.get("ImageId"), "ec2"
                )
            )

    with ThreadPoolExecutor(max_workers=8) as executor:
        executor.map(check_public_ami, images)


@inject_clients(clients=["ec2"])
def find_unencrypted_ebs_snapshots(ec2_client, findings, snapshots=None):
    if snapshots is None:
        snapshots = fetch_snapshots(ec2_client)

    def check_encryption(snapshot):
        if not snapshot.get("Encrypted", False):
            findings.append(
                new_vulnerability(
                    EC2Vulnerability.unencrypted_snapshot,
                    snapshot.get("SnapshotId"),
                    "ec2",
                )
            )

    with ThreadPoolExecutor(max_workers=8) as executor:
        executor.map(check_encryption, snapshots)


@inject_clients(clients=["ec2"])
def find_network_acls_allowing_all_traffic(ec2_client, findings):
    try:
        nacls = ec2_client.describe_network_acls().get("NetworkAcls", [])
    except Exception as e:
        logger.error(f"Error fetching NACLs: {e}")
        return

    def check_nacl(nacl):
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
                return

    with ThreadPoolExecutor(max_workers=8) as executor:
        executor.map(check_nacl, nacls)


@inject_clients(clients=["ec2"])
def find_route_tables_with_overly_permissive_routes(ec2_client, findings):
    try:
        route_tables = ec2_client.describe_route_tables().get("RouteTables", [])
    except Exception as e:
        logger.error(f"Error fetching route tables: {e}")
        return

    def check_route_table(rt):
        for route in rt.get("Routes", []):
            if route.get("DestinationCidrBlock") == "0.0.0.0/0":
                findings.append(
                    new_vulnerability(
                        EC2Vulnerability.route_table_open,
                        rt.get("RouteTableId"),
                        "ec2",
                    )
                )
                return

    with ThreadPoolExecutor(max_workers=8) as executor:
        executor.map(check_route_table, route_tables)


@inject_clients(clients=["ec2"])
def find_nat_gateways_without_eip(ec2_client, findings):
    try:
        nat_gateways = ec2_client.describe_nat_gateways().get("NatGateways", [])
    except Exception as e:
        logger.error(f"Error fetching NAT gateways: {e}")
        return

    def check_nat_eip(nat):
        if not nat.get("NatGatewayAddresses", [{}])[0].get("PublicIp"):
            findings.append(
                new_vulnerability(
                    EC2Vulnerability.nat_gateway_no_eip,
                    nat.get("NatGatewayId"),
                    "ec2",
                )
            )

    with ThreadPoolExecutor(max_workers=8) as executor:
        executor.map(check_nat_eip, nat_gateways)


@inject_clients(clients=["ec2"])
def find_vpn_connections_not_encrypted(ec2_client, findings):
    try:
        vpns = ec2_client.describe_vpn_connections().get("VpnConnections", [])
    except Exception as e:
        logger.error(f"Error fetching VPN connections: {e}")
        return

    def check_vpn_encryption(vpn):
        options = vpn.get("Options", {})
        if not options.get("TunnelEncryption", False):
            findings.append(
                new_vulnerability(
                    EC2Vulnerability.vpn_not_encrypted,
                    vpn.get("VpnConnectionId"),
                    "ec2",
                )
            )

    with ThreadPoolExecutor(max_workers=8) as executor:
        executor.map(check_vpn_encryption, vpns)


@inject_clients(clients=["ec2"])
def find_vpn_connections_not_authenticated(ec2_client, findings):
    try:
        vpns = ec2_client.describe_vpn_connections().get("VpnConnections", [])
    except Exception as e:
        logger.error(f"Error fetching VPN connections: {e}")
        return

    def check_vpn_auth(vpn):
        options = vpn.get("Options", {})
        if options.get("ReplayWindowSize", 0) == 0:
            findings.append(
                new_vulnerability(
                    EC2Vulnerability.vpn_not_authenticated,
                    vpn.get("VpnConnectionId"),
                    "ec2",
                )
            )

    with ThreadPoolExecutor(max_workers=8) as executor:
        executor.map(check_vpn_auth, vpns)


@inject_clients(clients=["ec2"])
def find_instances_without_ebs_delete_on_termination(
    ec2_client, findings, instances=None
):
    if instances is None:
        instances = fetch_instances(ec2_client)

    def check_delete_on_termination(instance):
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
                return

    with ThreadPoolExecutor(max_workers=8) as executor:
        executor.map(check_delete_on_termination, instances)


@inject_clients(clients=["ec2"])
def find_instances_without_iam_instance_profile(ec2_client, findings, instances=None):
    if instances is None:
        instances = fetch_instances(ec2_client)

    def check_iam_profile(instance):
        if not instance.get("IamInstanceProfile"):
            findings.append(
                new_vulnerability(
                    EC2Vulnerability.instance_no_iam_profile,
                    instance.get("InstanceId"),
                    "ec2",
                )
            )

    with ThreadPoolExecutor(max_workers=8) as executor:
        executor.map(check_iam_profile, instances)


@inject_clients(clients=["ec2"])
def find_instances_without_source_destination_check(
    ec2_client, findings, instances=None
):
    if instances is None:
        instances = fetch_instances(ec2_client)

    def check_source_dest(instance):
        for eni in instance.get("NetworkInterfaces", []):
            if eni.get("SourceDestCheck", True):
                findings.append(
                    new_vulnerability(
                        EC2Vulnerability.source_dest_check_enabled,
                        instance.get("InstanceId"),
                        "ec2",
                    )
                )
                return

    with ThreadPoolExecutor(max_workers=8) as executor:
        executor.map(check_source_dest, instances)


@inject_clients(clients=["ec2"])
def find_key_pairs_without_tags(ec2_client, findings):
    try:
        key_pairs = ec2_client.describe_key_pairs().get("KeyPairs", [])
    except Exception as e:
        logger.error(f"Error fetching key pairs: {e}")
        return

    def check_key_tags(key):
        if not key.get("Tags"):
            findings.append(
                new_vulnerability(
                    EC2Vulnerability.key_pair_no_tags, key.get("KeyName"), "ec2"
                )
            )

    with ThreadPoolExecutor(max_workers=8) as executor:
        executor.map(check_key_tags, key_pairs)


@inject_clients(clients=["ec2"])
def find_security_groups_without_description(
    ec2_client, findings, security_groups=None
):
    if security_groups is None:
        security_groups = fetch_security_groups(ec2_client)

    def check_description(sg):
        if not sg.get("GroupDescription"):
            findings.append(
                new_vulnerability(
                    EC2Vulnerability.sg_no_description, sg.get("GroupId"), "ec2"
                )
            )

    with ThreadPoolExecutor(max_workers=8) as executor:
        executor.map(check_description, security_groups)


@inject_clients(clients=["ec2"])
def find_instances_with_default_tenancy(ec2_client, findings, instances=None):
    if instances is None:
        instances = fetch_instances(ec2_client)

    def check_tenancy(instance):
        if instance.get("Tenancy") == "default":
            findings.append(
                new_vulnerability(
                    EC2Vulnerability.instance_default_tenancy,
                    instance.get("InstanceId"),
                    "ec2",
                )
            )

    with ThreadPoolExecutor(max_workers=8) as executor:
        executor.map(check_tenancy, instances)


@inject_clients(clients=["ec2"])
def find_instances_without_shutdown_behavior_stop(ec2_client, findings, instances=None):
    if instances is None:
        instances = fetch_instances(ec2_client)

    def check_shutdown_behavior(instance):
        instance_id = instance.get("InstanceId")
        try:
            attr = ec2_client.describe_instance_attribute(
                InstanceId=instance_id,
                Attribute="instanceInitiatedShutdownBehavior",
            )
            if attr.get("InstanceInitiatedShutdownBehavior", {}).get("Value") != "stop":
                findings.append(
                    new_vulnerability(
                        EC2Vulnerability.instance_shutdown_behavior,
                        instance_id,
                        "ec2",
                    )
                )
        except ClientError:
            pass

    with ThreadPoolExecutor(max_workers=8) as executor:
        executor.map(check_shutdown_behavior, instances)
