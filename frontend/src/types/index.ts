import type { components } from "@/openapi";

export type AWSCredentials = components["schemas"]["ValidateRequest"];
export type Finding = components["schemas"]["VulnerabilityFinding"];
export type ScanResponse = components["schemas"]["ScanResponse"];
export type BucketsResponse = components["schemas"]["BucketsResponse"];
export type FilesResponse = components["schemas"]["FilesResponse"];

export interface Service {
  id: string;
  name: string;
  description: string;
  icon: React.ComponentType<React.SVGProps<SVGSVGElement>>;
}
