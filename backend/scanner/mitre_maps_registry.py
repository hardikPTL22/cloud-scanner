from scanner.mitre_maps.s3_mitre_map import S3_SEVERITY, S3_MITRE_MAP
from scanner.mitre_maps.ec2_mitre_map import EC2_SEVERITY, EC2_MITRE_MAP
from scanner.mitre_maps.iam_mitre_map import IAM_SEVERITY, IAM_MITRE_MAP
from scanner.mitre_maps.ebs_mitre_map import EBS_SEVERITY, EBS_MITRE_MAP
from scanner.mitre_maps.cloudtrail_mitre_map import (
    CLOUDTRAIL_SEVERITY,
    CLOUDTRAIL_MITRE_MAP,
)
from scanner.mitre_maps.rds_mitre_map import RDS_SEVERITY, RDS_MITRE_MAP
from scanner.mitre_maps.ssm_mitre_map import SSM_SEVERITY, SSM_MITRE_MAP
from scanner.mitre_maps.lambda_mitre_map import LAMBDA_SEVERITY, LAMBDA_MITRE_MAP
from scanner.mitre_maps.apigateway_mitre_map import (
    APIGATEWAY_SEVERITY,
    APIGATEWAY_MITRE_MAP,
)
from scanner.mitre_maps.guardduty_mitre_map import (
    GUARDDUTY_SEVERITY,
    GUARDDUTY_MITRE_MAP,
)


SEVERITY_MAPS = {
    "s3": S3_SEVERITY,
    "ec2": EC2_SEVERITY,
    "iam": IAM_SEVERITY,
    "ebs": EBS_SEVERITY,
    "cloudtrail": CLOUDTRAIL_SEVERITY,
    "rds": RDS_SEVERITY,
    "ssm": SSM_SEVERITY,
    "lambda": LAMBDA_SEVERITY,
    "apigateway": APIGATEWAY_SEVERITY,
    "guardduty": GUARDDUTY_SEVERITY,
}


MITRE_MAPS = {
    "s3": S3_MITRE_MAP,
    "ec2": EC2_MITRE_MAP,
    "iam": IAM_MITRE_MAP,
    "ebs": EBS_MITRE_MAP,
    "cloudtrail": CLOUDTRAIL_MITRE_MAP,
    "rds": RDS_MITRE_MAP,
    "ssm": SSM_MITRE_MAP,
    "lambda": LAMBDA_MITRE_MAP,
    "apigateway": APIGATEWAY_MITRE_MAP,
    "guardduty": GUARDDUTY_MITRE_MAP,
}
