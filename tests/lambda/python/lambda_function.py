import json
import logging

# Set up logging to work in both Lambda and local environments
if len(logging.getLogger().handlers) > 0:
    # Running in Lambda; avoid adding duplicate handlers
    logging.getLogger().setLevel(logging.INFO)
else:
    # Running locally; use basicConfig
    logging.basicConfig(level=logging.INFO)

logger = logging.getLogger()

def handler(event, context):
    """
    This function processes an incoming event and returns a greeting.
    """
    logger.info("This log appears in CloudWatch")
    print("This print statement should also appear")
    try:
        print(f"EVENT PAYLOAD: {event}")
        # Extract name from the event, if provided
        if 'name' in event and event['name']:
            name = event['name']
        else:
            name = "World"

        # Safely stringify environment mapping before concatenation
        message = f"Hello, '{name}' from AWS Lambda with Python 3.11!"
        print(f"Sending return response: {message}")
        return {
            'statusCode': 200,
            'body': json.dumps(message)
        }
    except Exception as e:
        print(f"Error processing event: {e}")
        return {
            'statusCode': 500,
            'body': json.dumps(f"Error: {str(e)}")
        }
