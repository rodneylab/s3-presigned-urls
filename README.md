# s3-presigned-urls

Generate pre-signed URLs for fetching and putting files to S3 compatible storage with WASM.

Can be used with Deno and creates pre-signed URLs for multipart uploads.

Tested on Backblaze storage.

```shell
wasm-pack build --target web
```

For quick start, copy generated `pkg` folder to Deno project then in JavaScript/TypeScript:

```javascript
import init, {
  presigned_get_url,
  presigned_multipart_put_url,
  presigned_put_url,
} from "@/pkg/s3_presigned_urls.js";
import { cuid } from "cuid/index.js";

await init();

const uploadUrl = presigned_put_url(
      "my-movie.m2ts",
      "example-bucket",
      600,
      "AKIDEXAMPLE", // Account Id
      "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY". // account auth token
      `session-${cuid()}`,
    );
```

```javascript
import init, {
  presigned_get_url,
  presigned_multipart_put_url,
  presigned_put_url,
} from "@/pkg/s3_presigned_urls.js";
import { cuid } from "cuid/index.js";

await init();

const uploadUrl = presigned_multipart_put_url(
      "my-movie.m2ts",
      "example-bucket",
      600,
      4, // number of parts
      "your-upload-id",
      "AKIDEXAMPLE", // Account Id
      "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY". // account auth token
      `session-${cuid()}`,
    );
```
