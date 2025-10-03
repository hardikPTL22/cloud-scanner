import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import type { Service } from "@/types";

import S3Icon from "@/assets/s3.svg?react";
import IAMIcon from "@/assets/iam.svg?react";
import EC2Icon from "@/assets/ec2.svg?react";
import CloudTrailIcon from "@/assets/cloudtrail.svg?react";
import GuardDutyIcon from "@/assets/guardduty.svg?react";
import LambdaIcon from "@/assets/lambda.svg?react";
import RDSIcon from "@/assets/rds.svg?react";
import EBSIcon from "@/assets/ebs.svg?react";
import SSMIcon from "@/assets/ssm.svg?react";
import APIGatewayIcon from "@/assets/apigateway.svg?react";
import {
  Accordion,
  AccordionContent,
  AccordionItem,
  AccordionTrigger,
} from "./ui/accordion";
import { RESOURCES_MAP } from "@/lib/resource-map";
import { Checkbox } from "./ui/checkbox";
import { InfoIcon } from "lucide-react";
import { Tooltip, TooltipContent, TooltipTrigger } from "./ui/tooltip";

const descriptions: Record<string, string> = {
  public_s3_bucket: "Detects S3 buckets with public read/write access",
  s3_bucket_versioning_disabled:
    "Identifies S3 buckets without versioning enabled",
  s3_bucket_logging_disabled: "Finds S3 buckets without access logging",
  s3_bucket_block_public_access_disabled:
    "Checks for disabled public access blocking",
  unencrypted_s3_bucket: "Identifies unencrypted S3 buckets",
  vpc_flow_logs_disabled: "Detects VPCs without flow logs enabled",
  over_permissive_iam: "Finds overly permissive IAM policies",
  iam_user_no_mfa: "Identifies IAM users without MFA enabled",
  iam_unused_access_key: "Detects unused IAM access keys",
  iam_inline_policy: "Finds IAM users with inline policies",
  iam_root_access_key: "Detects root account access keys",
  iam_user_with_console_access: "Identifies IAM users with console access",
  open_security_group_ingress: "Finds security groups with open ingress rules",
  open_security_group_egress: "Detects security groups with open egress rules",
  unused_security_group: "Identifies unused security groups",
  ec2_instance_public_ip: "Finds EC2 instances with public IP addresses",
  cloudtrail_not_logging: "Detects CloudTrail trails not logging",
  cloudtrail_not_multi_region: "Finds single-region CloudTrail configurations",
  cloudtrail_no_log_file_validation: "Checks for disabled log file validation",
  cloudtrail_bucket_public: "Detects public CloudTrail S3 buckets",
  cloudtrail_bucket_encryption_disabled: "Finds unencrypted CloudTrail buckets",
  guardduty_disabled: "Detects disabled GuardDuty in regions",
  ebs_volume_unencrypted: "Identifies unencrypted EBS volumes",
  rds_instance_unencrypted: "Finds unencrypted RDS instances",
  rds_instance_public_access: "Detects RDS instances with public access",
  ssm_parameter_unencrypted: "Identifies unencrypted SSM parameters",
  lambda_overpermissive_role:
    "Finds Lambda functions with excessive permissions",
  lambda_public_access: "Detects publicly accessible Lambda functions",
  apigateway_open_resource:
    "Identifies API Gateway resources without authentication",
};

const services: Service[] = [
  {
    id: "s3",
    name: "S3",
    description: "Simple Storage Service",
    icon: S3Icon,
  },
  {
    id: "iam",
    name: "IAM",
    description: "Identity and Access Management",
    icon: IAMIcon,
  },
  {
    id: "ec2",
    name: "EC2",
    description: "Elastic Compute Cloud",
    icon: EC2Icon,
  },
  {
    id: "cloudtrail",
    name: "CloudTrail",
    description: "AWS CloudTrail",
    icon: CloudTrailIcon,
  },
  {
    id: "guardduty",
    name: "GuardDuty",
    description: "Threat Detection Service",
    icon: GuardDutyIcon,
  },
  {
    id: "lambda",
    name: "Lambda",
    description: "Serverless Computing",
    icon: LambdaIcon,
  },
  {
    id: "rds",
    name: "RDS",
    description: "Relational Database Service",
    icon: RDSIcon,
  },
  {
    id: "ebs",
    name: "EBS",
    description: "Elastic Block Store",
    icon: EBSIcon,
  },
  {
    id: "ssm",
    name: "SSM",
    description: "Systems Manager",
    icon: SSMIcon,
  },
  {
    id: "apigateway",
    name: "API Gateway",
    description: "API Management",
    icon: APIGatewayIcon,
  },
];

interface ServiceSelectorProps {
  selectedServices: Record<string, string[]>;
  onSelectionChange: (services: Record<string, string[]>) => void;
}

export function ServiceSelector({
  selectedServices,
  onSelectionChange,
}: ServiceSelectorProps) {
  const handleServiceToggle = (serviceId: string, checked: boolean) => {
    if (checked) {
      onSelectionChange({
        ...selectedServices,
        [serviceId]: RESOURCES_MAP[serviceId] ?? [],
      });
    } else {
      delete selectedServices[serviceId];
      onSelectionChange({ ...selectedServices });
    }
  };

  const handleSelectAll = () => {
    if (Object.keys(selectedServices).length === services.length) {
      onSelectionChange({});
    } else {
      onSelectionChange(
        services.reduce((acc, s) => {
          acc[s.id] = RESOURCES_MAP[s.id] ?? [];
          return acc;
        }, {} as Record<string, string[]>)
      );
    }
  };

  return (
    <Card>
      <CardHeader className="pb-3">
        <div className="flex items-center justify-between">
          <CardTitle>AWS Services to Scan</CardTitle>
          <button
            onClick={handleSelectAll}
            className="text-sm text-primary hover:underline"
          >
            {Object.keys(selectedServices).length === services.length
              ? "Deselect All"
              : "Select All"}
          </button>
        </div>
      </CardHeader>
      <CardContent>
        <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-5 gap-4">
          {services.map((service) => {
            const IconComponent = service.icon;
            const isSelected = selectedServices[service.id] !== undefined;

            return (
              <div
                key={service.id}
                className={`flex flex-col items-center p-3 rounded-lg border cursor-pointer transition-all hover:bg-accent/50 ${
                  isSelected ? "bg-accent border-primary" : "border-border"
                }`}
                onClick={() => handleServiceToggle(service.id, !isSelected)}
              >
                <div className="flex items-center justify-center w-12 h-12 mb-2">
                  <IconComponent className="w-8 h-8" />
                </div>
                <div className="text-center">
                  <div className="font-medium text-sm">{service.name}</div>
                  <div className="text-xs text-muted-foreground">
                    {service.description}
                  </div>
                </div>
              </div>
            );
          })}
        </div>
        <Accordion type="single" collapsible className="w-full mt-4">
          <AccordionItem value="advanced-config">
            <AccordionTrigger>
              <div className="text-sm text-muted-foreground">
                Advanced configuration (optional)
              </div>
            </AccordionTrigger>
            <AccordionContent>
              <div className="flex flex-col text-accent-foreground gap-y-4 items-start">
                {Object.entries(selectedServices).map(([service, scans]) => (
                  <>
                    <div className="font-semibold">{service}</div>
                    <div className="grid grid-cols-3 gap-2 w-full">
                      {RESOURCES_MAP[service]?.map((scan) => (
                        <div className="flex items-center gap-2">
                          <Checkbox
                            checked={scans.includes(scan)}
                            onCheckedChange={(checked) => {
                              checked = Boolean(checked);
                              if (checked) {
                                onSelectionChange({
                                  ...selectedServices,
                                  [service]: Array.from(
                                    new Set([...scans, scan])
                                  ),
                                });
                              } else {
                                onSelectionChange({
                                  ...selectedServices,
                                  [service]: scans.filter((s) => s !== scan),
                                });
                              }
                            }}
                          />
                          <span>
                            {scan
                              .split("_")
                              .map(
                                (word) =>
                                  word.charAt(0).toUpperCase() + word.slice(1)
                              )
                              .join(" ")}
                          </span>
                          <Tooltip>
                            <TooltipTrigger>
                              <InfoIcon className="size-3" strokeWidth={1} />
                            </TooltipTrigger>
                            <TooltipContent>
                              {descriptions[scan] ?? "No description available"}
                            </TooltipContent>
                          </Tooltip>
                        </div>
                      ))}
                    </div>
                  </>
                ))}
              </div>
            </AccordionContent>
          </AccordionItem>
        </Accordion>
        {Object.keys(selectedServices).length === 0 && (
          <div className="text-center text-muted-foreground text-sm mt-4">
            Select at least one service to scan
          </div>
        )}
      </CardContent>
    </Card>
  );
}
