const { SQSClient, SendMessageCommand } = require("@aws-sdk/client-sqs");

exports.handler = async (event) => {
  console.log("=== Lambda Invocation Started ===");
  console.log("Environment Variables:");
  console.log("  AWS_REGION:", process.env.AWS_REGION);
  console.log("  AWS_ENDPOINT_URL:", process.env.AWS_ENDPOINT_URL);
  console.log("  AWS_ENDPOINT_URL_SQS:", process.env.AWS_ENDPOINT_URL_SQS);
  console.log("  RESULT_QUEUE_URL:", process.env.RESULT_QUEUE_URL);
  
  console.log("\nReceived Event:");
  console.log(JSON.stringify(event, null, 2));
  
  const resultQueueUrl = process.env.RESULT_QUEUE_URL;
  
  if (!resultQueueUrl) {
    console.error("ERROR: RESULT_QUEUE_URL environment variable is not set!");
    return { 
      statusCode: 500, 
      body: JSON.stringify({ error: "RESULT_QUEUE_URL not configured" })
    };
  }
  
  // Use SQS-specific endpoint if available, otherwise fall back to general endpoint
  const sqsEndpoint = process.env.AWS_ENDPOINT_URL_SQS || process.env.AWS_ENDPOINT_URL;
  console.log("\nSQS Client Configuration:");
  console.log("  Using endpoint:", sqsEndpoint);
  
  const sqs = new SQSClient({
    region: process.env.AWS_REGION || "ap-southeast-2",
    endpoint: sqsEndpoint,
  });
  
  const results = {
    processed: 0,
    failed: 0,
    errors: []
  };
  
  for (const record of event.Records) {
    try {
      const body = record.body;
      console.log(`\nProcessing record ${record.messageId}:`);
      console.log("  Body:", body);
      
      console.log(`  Sending to queue: ${resultQueueUrl}`);
      
      const command = new SendMessageCommand({
        QueueUrl: resultQueueUrl,
        MessageBody: body
      });
      
      const response = await sqs.send(command);
      
      console.log("  Success! MessageId:", response.MessageId);
      results.processed++;
      
    } catch (error) {
      console.error(`  ✗ Failed to process record ${record.messageId}`);
      console.error("  Error Type:", error.constructor.name);
      console.error("  Error Message:", error.message);
      
      // Log the raw response if available
      if (error.$response) {
        console.error("  HTTP Status:", error.$response.statusCode);
        console.error("  Response Headers:", JSON.stringify(error.$response.headers, null, 2));
        
        // Try to log raw body
        if (error.$response.body) {
          try {
            const bodyText = error.$response.body.toString();
            console.error("  Raw Response Body (first 500 chars):", bodyText.substring(0, 500));
          } catch (e) {
            console.error("  Could not read response body:", e.message);
          }
        }
      }
      
      // Log full error object for debugging
      console.error("  Full Error:", JSON.stringify(error, Object.getOwnPropertyNames(error), 2));
      
      results.failed++;
      results.errors.push({
        messageId: record.messageId,
        error: error.message,
        type: error.constructor.name
      });
    }
  }
  
  console.log("\n=== Processing Summary ===");
  console.log("  Processed:", results.processed);
  console.log("  Failed:", results.failed);
  
  if (results.errors.length > 0) {
    console.log("  Errors:", JSON.stringify(results.errors, null, 2));
  }
  
  console.log("=== Lambda Invocation Complete ===");
  
  return {
    statusCode: results.failed > 0 ? 500 : 200,
    body: JSON.stringify(results)
  };
};