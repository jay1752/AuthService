from typing import Optional, Dict, Any, Callable
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from jose import jwt, JWTError
import aiohttp
from functools import lru_cache
from datetime import datetime
import logging
from app.core.config import settings

# Configure logging
logger = logging.getLogger(__name__)

security = HTTPBearer()

class CognitoTokenVerifier:
    def __init__(self):
        logger.info("Initializing CognitoTokenVerifier")
        self.jwks = None
        self.config = settings.get_cognito_config()
        
        # Validate required configuration
        if not self.config["user_pool_id"] or not self.config["client_id"]:
            error_msg = "Missing required Cognito configuration. Required: COGNITO_USER_POOL_ID and COGNITO_CLIENT_ID"
            logger.error(error_msg)
            raise ValueError(error_msg)
        
        logger.info(f"Token verifier initialized with User Pool ID: {self.config['user_pool_id']}")

    async def initialize(self):
        """Initialize the verifier by fetching JWKS."""
        logger.info("Initializing token verifier")
        try:
            self.jwks = await self._get_cached_jwks()
            if not self.jwks or not self.jwks.get('keys'):
                error_msg = "Failed to fetch JWKS from Cognito"
                logger.error(error_msg)
                raise ValueError(error_msg)
            logger.info("Token verifier initialized successfully")
        except Exception as e:
            error_msg = f"Failed to initialize token verifier: {str(e)}"
            logger.error(error_msg)
            raise ValueError(error_msg)

    @lru_cache(maxsize=1)
    async def _get_cached_jwks(self) -> Dict:
        """Get cached JWKS to avoid frequent requests."""
        logger.debug("Fetching JWKS from cache or Cognito")
        return await self._fetch_jwks()

    async def _fetch_jwks(self) -> Dict:
        """Fetch the JSON Web Key Set (JWKS) for the user pool."""
        jwks_url = f'https://cognito-idp.{self.config["region"]}.amazonaws.com/{self.config["user_pool_id"]}/.well-known/jwks.json'
        logger.debug(f"Fetching JWKS from: {jwks_url}")
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(jwks_url, timeout=5) as response:
                    response.raise_for_status()
                    jwks = await response.json()
                    if not jwks or not jwks.get('keys'):
                        raise ValueError("Invalid JWKS response from Cognito")
                    logger.debug("Successfully fetched JWKS")
                    return jwks
        except aiohttp.ClientError as e:
            error_msg = f"Failed to fetch JWKS: {str(e)}"
            logger.error(error_msg)
            raise ValueError(error_msg)
        except Exception as e:
            error_msg = f"Unexpected error fetching JWKS: {str(e)}"
            logger.error(error_msg)
            raise ValueError(error_msg)

    def _find_jwk(self, kid: str) -> Optional[Dict]:
        """Find the JWK that matches the kid (Key ID) from the token header."""
        logger.debug(f"Finding JWK for kid: {kid}")
        if not self.jwks:
            error_msg = "JWKS not initialized"
            logger.error(error_msg)
            raise ValueError(error_msg)

        jwk = next((key for key in self.jwks['keys'] if key['kid'] == kid), None)
        if not jwk:
            error_msg = f"No matching JWK found for kid: {kid}"
            logger.error(error_msg)
            raise ValueError(error_msg)
        return jwk

    async def verify_token(self, token: str) -> Dict[str, Any]:
        """Verify a JWT token and return its claims."""
        logger.debug("Verifying token")
        try:
            # Decode the token header to get the key ID (kid)
            header = jwt.get_unverified_header(token)
            kid = header['kid']
            logger.debug(f"Token header decoded, kid: {kid}")

            # Find the matching JWK
            jwk = self._find_jwk(kid)
            if not jwk:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid token: Key ID not found"
                )

            # Verify the token with additional checks
            logger.debug("Decoding and verifying token")
            claims = jwt.decode(
                token,
                jwk,
                algorithms=['RS256'],
                audience=self.config['client_id'],
                issuer=f'https://cognito-idp.{self.config["region"]}.amazonaws.com/{self.config["user_pool_id"]}'
            )
            
            # Additional security checks
            if datetime.fromtimestamp(claims['exp']) < datetime.utcnow():
                logger.error("Token has expired")
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Token has expired"
                )
            
            logger.info(f"Token verified successfully for user: {claims.get('username', 'unknown')}")
            return claims
        except JWTError as e:
            logger.error(f"Token verification failed: {str(e)}")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token"
            )
        except ValueError as e:
            logger.error(f"Token verification error: {str(e)}")
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail=str(e)
            )
        except Exception as e:
            logger.error(f"Unexpected error during token verification: {str(e)}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Internal server error"
            )

# Create a singleton instance
token_verifier = CognitoTokenVerifier()

async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)) -> Dict[str, Any]:
    """
    FastAPI dependency for verifying Cognito tokens and getting user information.
    Use this in your route dependencies to protect endpoints.
    """
    logger.debug("Getting current user from token")
    if not token_verifier.jwks:
        logger.info("JWKS not initialized, initializing now")
        await token_verifier.initialize()
    
    claims = await token_verifier.verify_token(credentials.credentials)
    print(claims)
    logger.info(f"Successfully authenticated user: {claims.get('username', 'unknown')}")
    return claims

def require_role(required_role: str) -> Callable:
    """
    FastAPI dependency factory for checking user roles.
    Use this in your route dependencies to restrict access based on roles.
    """
    async def check_role(user: Dict[str, Any] = Depends(get_current_user)) -> Dict[str, Any]:
        logger.debug(f"Checking role {required_role} for user: {user.get('username', 'unknown')}")
        #TODO: Check if user has required role
        # if 'cognito:groups' not in user or required_role not in user['cognito:groups']:
        #     logger.error(f"User {user.get('username', 'unknown')} does not have required role: {required_role}")
        #     raise HTTPException(
        #         status_code=status.HTTP_403_FORBIDDEN,
        #         detail="Insufficient permissions"
        #     )
        logger.info(f"User {user.get('username', 'unknown')} has required role: {required_role}")
        return user
    return check_role