const { S3Client, PutObjectCommand } = require("@aws-sdk/client-s3");

// Test R2 connection
async function testR2() {
  const R2_ENDPOINT = "https://3a969efa675cb4925f2ec27a2310ea.r2.cloudflarestorage.com";
  const R2_ACCESS_KEY_ID = "64d02f9df8c034b992dbdaf0623f2b1c";
  const R2_SECRET_ACCESS_KEY = "7e90da752fd66a772f5d80bf57b7b85aae4a013c063f34e80bc1901afac9ce77";
  const R2_BUCKET = "bluevideos";

  console.log("Testing R2 connection...");
  console.log("Endpoint:", R2_ENDPOINT);
  console.log("Access Key ID:", R2_ACCESS_KEY_ID);
  console.log("Bucket:", R2_BUCKET);

  // Try with different TLS settings
  process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0'; // Temporarily disable TLS verification for testing

  const s3Client = new S3Client({
    region: "auto",
    endpoint: R2_ENDPOINT,
    forcePathStyle: true,
    credentials: {
      accessKeyId: R2_ACCESS_KEY_ID,
      secretAccessKey: R2_SECRET_ACCESS_KEY,
    },
    requestHandler: {
      httpsAgent: {
        rejectUnauthorized: false
      }
    }
  });

  try {
    // Test with a small text file
    const testData = Buffer.from("Hello R2 test", "utf-8");
    const command = new PutObjectCommand({
      Bucket: R2_BUCKET,
      Key: "test-file.txt",
      Body: testData,
      ContentType: "text/plain",
    });

    console.log("Attempting to upload test file...");
    const result = await s3Client.send(command);
    console.log("✅ R2 upload successful:", result);
  } catch (error) {
    console.error("❌ R2 upload failed:", error);
    console.error("Error details:", {
      name: error.name,
      message: error.message,
      code: error.code,
      statusCode: error.$metadata?.httpStatusCode,
    });
  }
}

testR2();