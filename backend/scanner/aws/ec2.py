from scanner.mitre_map import Vulnerability, new_vulnerability
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
                            Vulnerability.open_security_group_ingress, sg_name
                        )
                    )
                    break
            for ip_range in perm.get("Ipv6Ranges", []):
                if ip_range.get("CidrIpv6") == "::/0":
                    findings.append(
                        new_vulnerability(
                            Vulnerability.open_security_group_ingress, sg_name
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
                            Vulnerability.open_security_group_egress, sg_name
                        )
                    )
                    break
            for ip_range in perm.get("Ipv6Ranges", []):
                if ip_range.get("CidrIpv6") == "::/0":
                    findings.append(
                        new_vulnerability(
                            Vulnerability.open_security_group_egress, sg_name
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
                new_vulnerability(Vulnerability.unused_security_group, sg_id)
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
                new_vulnerability(Vulnerability.vpc_flow_logs_disabled, vpc_id)
            )


@inject_clients(clients=["ec2"])
def find_ebs_unencrypted(ec2_client, findings):
    volumes = ec2_client.describe_volumes().get("Volumes", [])
    for vol in volumes:
        if not vol.get("Encrypted", False):
            findings.append(
                new_vulnerability(Vulnerability.ebs_volume_unencrypted, vol["VolumeId"])
            )


@inject_clients(clients=["ec2"])
def find_ec2_instance_public_ip(ec2_client, findings):
    reservations = ec2_client.describe_instances().get("Reservations", [])
    for reservation in reservations:
        for instance in reservation.get("Instances", []):
            if instance.get("PublicIpAddress"):
                findings.append(
                    new_vulnerability(
                        Vulnerability.ec2_instance_public_ip,
                        instance.get("InstanceId"),
                    )
                )


@inject_clients(clients=["ec2"])
def find_security_groups_with_open_ports(ec2_client, findings):
    security_groups = ec2_client.describe_security_groups().get("SecurityGroups", [])
    for sg in security_groups:
        sg_name = sg.get("GroupName") or sg.get("GroupId")
        for perm in sg.get("IpPermissions", []):
            for ip_range in perm.get("IpRanges", []):
                if ip_range.get("CidrIp") == "0.0.0.0/0":
                    findings.append(
                        {
                            "type": Vulnerability.open_security_group_ingress,
                            "name": sg_name,
                            "severity": "High",
                            "details": "Security group ingress open to the world.",
                        }
                    )
                    break
