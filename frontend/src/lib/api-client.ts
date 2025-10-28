import createFetchClient, { type Middleware } from "openapi-fetch";
import createClient from "openapi-react-query";
import type { paths } from "../openapi.d.ts";
import { useAWSStore } from "@/lib/aws-store.ts";

const authMiddleware: Middleware = {
  onRequest({ request }) {
    const awsCredentials = useAWSStore.getState().credentials;

    if (awsCredentials) {
      request.headers.set("X-AWS-Access-Key", awsCredentials.accessKey);
      request.headers.set("X-AWS-Secret-Key", awsCredentials.secretKey);
      request.headers.set("X-AWS-Region", awsCredentials.region);
    }

    return request;
  },
};

const client = createFetchClient<paths>({ baseUrl: "http://localhost:5000" });
export const api = createClient(client);

client.use(authMiddleware);
