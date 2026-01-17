import json

def handler(event, context):
    """
    This function processes an incoming event and returns a greeting.
    """
    try:
        # Extract name from the event, if provided
        if 'name' in event and event['name']:
            name = event['name']
        else:
            name = "World"

        message = f"Hello, '{name}' from AWS Lambda with Python 3.11!"

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

