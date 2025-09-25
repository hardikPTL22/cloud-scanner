export interface AWSCredentials {
  accessKey: string;
  secretKey: string;
  region: string;
}

export interface Finding {
  type: string;
  name: string;
  severity: 'High' | 'Medium' | 'Low';
  details: string;
}

export interface ScanResponse {
  findings: Finding[];
}

export interface BucketsResponse {
  buckets: string[];
}

export interface FilesResponse {
  files: string[];
}