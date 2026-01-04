export const CONTROL_MAPPING: Record<
  string,
  { iso: string; nist: string; cis: string }
> = {
  public_s3_bucket: {
    iso: "A.8.2",
    nist: "PR.AC-3",
    cis: "CIS 3.1",
  },
  unencrypted_s3_bucket: {
    iso: "A.10.1",
    nist: "PR.DS-1",
    cis: "CIS 2.2",
  },
};
