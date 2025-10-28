import type { components } from "@/openapi";

export interface AWSCredentials {
  accessKey: string;
  secretKey: string;
  region: string;
}

export type Finding = components["schemas"]["VulnerabilityFinding"];
export type ScanResponse = components["schemas"]["ScanResponse"];

export interface Service {
  id: string;
  name: string;
  description: string;
  icon: React.ComponentType<React.SVGProps<SVGSVGElement>>;
}

export type BucketsResponse = components["schemas"]["BucketsResponse"];

export type FilesResponse = components["schemas"]["FilesResponse"];
