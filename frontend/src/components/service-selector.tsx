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
  selectedServices: string[];
  onSelectionChange: (services: string[]) => void;
}

export function ServiceSelector({
  selectedServices,
  onSelectionChange,
}: ServiceSelectorProps) {
  const handleServiceToggle = (serviceId: string, checked: boolean) => {
    if (checked) {
      onSelectionChange([...selectedServices, serviceId]);
    } else {
      onSelectionChange(selectedServices.filter((id) => id !== serviceId));
    }
  };

  const handleSelectAll = () => {
    if (selectedServices.length === services.length) {
      onSelectionChange([]);
    } else {
      onSelectionChange(services.map((s) => s.id));
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
            {selectedServices.length === services.length
              ? "Deselect All"
              : "Select All"}
          </button>
        </div>
      </CardHeader>
      <CardContent>
        <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-5 gap-4">
          {services.map((service) => {
            const IconComponent = service.icon;
            const isSelected = selectedServices.includes(service.id);

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
        {selectedServices.length === 0 && (
          <div className="text-center text-muted-foreground text-sm mt-4">
            Select at least one service to scan
          </div>
        )}
      </CardContent>
    </Card>
  );
}
