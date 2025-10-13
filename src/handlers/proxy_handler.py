"""Main Lambda handler for the Authru."""
import sys
from pathlib import Path
from typing import Dict, Any

# Add src directory to Python path for proper imports
src_path = str(Path(__file__).parent.parent)
if src_path not in sys.path:
    sys.path.insert(0, src_path)

from services.proxy_service import ProxyService, ProxyError
from utils.logger import get_logger, log_request, log_response

logger = get_logger(__name__) 

# Global instances for Lambda container reuse
proxy_service = ProxyService()

def lambda_handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """Main Lambda handler for proxy requests.

    Args:
        event: API Gateway event object.
        context: Lambda context object.

    Returns:
        Dict: API Gateway response object.
    """
    try:
        log_request(logger, event)
        proxy_response = proxy_service.forward_request(event)
        log_response(logger,
                     proxy_response.status_code,
                     len(proxy_response.body))
        return {"statusCode": proxy_response.status_code,
                "headers": proxy_response.headers,
                "body": proxy_response.body}
    except ProxyError as e:
        logger.error("Unexpected error in proxy handler: %s", e, exc_info=True)
        return {"statusCode": 500,
                "headers": {},
                "body": "Internal server error"}
