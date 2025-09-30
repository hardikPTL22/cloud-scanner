import type { AWSCredentials, ScanResponse, BucketsResponse, FilesResponse } from '@/types';

const BASE_URL = 'http://localhost:5000';

const createHeaders = (credentials: AWSCredentials) => ({
  'Content-Type': 'application/json',
  'X-AWS-Access-Key': credentials.accessKey,
  'X-AWS-Secret-Key': credentials.secretKey,
  'X-AWS-Region': credentials.region,
});

export const apiService = {
  async validateCredentials(credentials: AWSCredentials): Promise<boolean> {
    try {
      const response = await fetch(`${BASE_URL}/api/validate`, {
        method: 'GET',
        headers: createHeaders(credentials),
      });
      return response.ok;
    } catch {
      return false;
    }
  },

  async getBuckets(credentials: AWSCredentials): Promise<string[]> {
    const response = await fetch(`${BASE_URL}/api/buckets`, {
      method: 'GET',
      headers: createHeaders(credentials),
    });

    if (!response.ok) {
      throw new Error(`Failed to fetch buckets: ${response.statusText}`);
    }

    const data: BucketsResponse = await response.json();
    return data.buckets;
  },

  async getFiles(credentials: AWSCredentials, bucket: string): Promise<string[]> {
    const response = await fetch(`${BASE_URL}/api/files?bucket=${encodeURIComponent(bucket)}`, {
      method: 'GET',
      headers: createHeaders(credentials),
    });

    if (!response.ok) {
      throw new Error(`Failed to fetch files: ${response.statusText}`);
    }

    const data: FilesResponse = await response.json();
    return data.files;
  },

  async scan(credentials: AWSCredentials, services: string[], bucket?: string, file?: string): Promise<ScanResponse> {
    const body: any = {};
    body.services = services;
    if (bucket) body.bucket = bucket;
    if (file) body.file = file;

    const response = await fetch(`${BASE_URL}/api/scan`, {
      method: 'POST',
      headers: createHeaders(credentials),
      body: JSON.stringify(body),
    });

    if (!response.ok) {
      throw new Error(`Scan failed: ${response.statusText}`);
    }

    return await response.json();
  },

  async downloadReport(credentials: AWSCredentials, findings: any[], format: 'csv' | 'json' | 'pdf'): Promise<Blob> {
    const response = await fetch(`${BASE_URL}/api/report`, {
      method: 'POST',
      headers: createHeaders(credentials),
      body: JSON.stringify({
        findings,
        format,
      }),
    });

    if (!response.ok) {
      throw new Error(`Report generation failed: ${response.statusText}`);
    }

    return await response.blob();
  },
};