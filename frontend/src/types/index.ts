export interface AWSCredentials {
  accessKey: string;
  secretKey: string;
  region: string;
}

export interface Finding {
  type: string;
  name: string;
  severity: "High" | "Medium" | "Low";
  details: string;
}

export interface ScanResponse {
  scan_id: string;
  findings: Finding[];
}

export interface Service {
  id: string;
  name: string;
  description: string;
  icon: React.ComponentType<React.SVGProps<SVGSVGElement>>;
}

export interface BucketsResponse {
  buckets: string[];
}

export interface FilesResponse {
  files: string[];
}
