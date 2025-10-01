from scanner.mitre_map import Vulnerability, new_vulnerability


def find_security_groups_open_ingress(ec2_client, findings):
    open_groups = []
    response = ec2_client.describe_security_groups()
    for sg in response.get("SecurityGroups", []):
        for perm in sg.get("IpPermissions", []):
            for ip_range in perm.get("IpRanges", []):
                if ip_range.get("CidrIp") == "0.0.0.0/0":
                    open_groups.append(sg.get("GroupName") or sg.get("GroupId"))
                    break
            for ip_range in perm.get("Ipv6Ranges", []):
                if ip_range.get("CidrIpv6") == "::/0":
                    open_groups.append(sg.get("GroupName") or sg.get("GroupId"))
                    break
    for sg in open_groups:
        findings.append(
            new_vulnerability(
                Vulnerability.open_security_group_ingress,
                sg,
            )
        )


def find_security_groups_open_egress(ec2_client, findings):
    open_egress = []
    response = ec2_client.describe_security_groups()
    for sg in response.get("SecurityGroups", []):
        for perm in sg.get("IpPermissionsEgress", []):
            for ip_range in perm.get("IpRanges", []):
                if ip_range.get("CidrIp") == "0.0.0.0/0":
                    open_egress.append(sg.get("GroupName") or sg.get("GroupId"))
                    break
            for ip_range in perm.get("Ipv6Ranges", []):
                if ip_range.get("CidrIpv6") == "::/0":
                    open_egress.append(sg.get("GroupName") or sg.get("GroupId"))
                    break
    for sg in open_egress:
        findings.append(
            new_vulnerability(
                Vulnerability.open_security_group_egress,
                sg,
            )
        )


def find_unused_security_groups(ec2_client, findings):
    unused_groups = []
    response = ec2_client.describe_security_groups()
    for sg in response.get("SecurityGroups", []):
        attachments = sg.get("Attachments", [])
        # In some API versions this may not exist, fallback to checking if GroupName matches anything
        if not attachments:
            # Rough check, further improvements may be needed
            unused_groups.append(sg.get("GroupName") or sg.get("GroupId"))
    for sg in unused_groups:
        findings.append(
            new_vulnerability(
                Vulnerability.unused_security_group,
                sg,
            )
        )


def find_vpc_flow_logs_disabled(ec2_client, findings):
    disabled = []
    vpcs_resp = ec2_client.describe_vpcs()
    for vpc in vpcs_resp.get("Vpcs", []):
        vpc_id = vpc.get("VpcId")
        flow_logs_resp = ec2_client.describe_flow_logs(
            Filters=[{"Name": "resource-id", "Values": [vpc_id]}]
        )
        if not flow_logs_resp.get("FlowLogs"):
            disabled.append(vpc_id)
    for vpc in disabled:
        findings.append(
            new_vulnerability(
                Vulnerability.vpc_flow_logs_disabled,
                vpc,
            )
        )


def find_ebs_unencrypted(ec2_client, findings):
    unencrypted = []
    volumes_resp = ec2_client.describe_volumes()
    for vol in volumes_resp.get("Volumes", []):
        vol_id = vol.get("VolumeId")
        if not vol.get("Encrypted", False):
            unencrypted.append(vol_id)
    for vol in unencrypted:
        findings.append(
            new_vulnerability(
                Vulnerability.ebs_volume_unencrypted,
                vol,
            )
        )
