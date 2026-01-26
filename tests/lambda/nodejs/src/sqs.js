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

  const endpoint = process.env.AWS_ENDPOINT_URL;
  console.log("\nSQS Client Configuration:");
  console.log("  Using endpoint URL:", endpoint);

  const sqs = new SQSClient({
    region: process.env.AWS_REGION || "ap-southeast-2",
    endpoint: endpoint,
  });

  const results = {
    processed: 0,
    failed: 0,
    errors: []
  };

  for (const record of event.Records || []) {
    try {
      const source = record.eventSource || record.EventSource || "unknown";
      let messageBody, messageId;

      // Handle both SQS and DDB as event soruces
      if (source === "aws:sqs") {
        messageBody = record.body;
        messageId = record.messageId;
      } else if (source === "aws:dynamodb") {
        // Serialize DDB record safely, converting datetimes
        messageBody = JSON.stringify(record.dynamodb, (_, v) =>
          v instanceof Date ? v.toISOString() : v
        );
        messageId = record.eventID;
      } else {
        console.warn(`Unknown event source: ${source}`);
        continue;
      }

      console.log(`\nProcessing record ${messageId} from ${source}`);
      console.log(`  Sending to queue: ${resultQueueUrl}`);

      const command = new SendMessageCommand({
        QueueUrl: resultQueueUrl,
        MessageBody: messageBody,
      });

      const response = await sqs.send(command);

      console.log("  Success! MessageId:", response.MessageId);
      results.processed++;
    } catch (error) {
      console.error(`  ✗ Failed to process record`);
      console.error("  Error Type:", error.constructor.name);
      console.error("  Error Message:", error.message);

      results.failed++;
      results.errors.push({
        error: error.message,
        type: error.constructor.name,
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
    body: JSON.stringify(results),
  };
};
