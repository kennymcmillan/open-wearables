import logging
from uuid import UUID

import httpx

from app.config import settings
from app.database import DbSession
from app.schemas import (
    AuthenticationMethod,
    OAuthTokenResponse,
    ProviderCredentials,
    ProviderEndpoints,
)
from app.services.providers.templates.base_oauth import BaseOAuthTemplate
from app.utils.structured_logging import log_structured

logger = logging.getLogger(__name__)

# WHOOP requires `offline` scope to issue a refresh token.
# All other scopes needed for full data access:
WHOOP_REQUIRED_SCOPE = "offline read:cycles read:sleep read:recovery read:workout read:profile read:body_measurement"


class WhoopOAuth(BaseOAuthTemplate):
    """Whoop OAuth 2.0 implementation with production safeguards.

    Key WHOOP OAuth quirks:
    1. `offline` MUST be in scope — without it WHOOP won't return a refresh token.
    2. Refresh tokens are single-use — the new refresh token must be stored immediately.
    3. Including `scope` in refresh requests ensures WHOOP re-issues the full scope.
    4. Token verification after DB write catches silent storage failures.
    """

    @property
    def endpoints(self) -> ProviderEndpoints:
        """OAuth endpoints for authorization and token exchange."""
        return ProviderEndpoints(
            authorize_url="https://api.prod.whoop.com/oauth/oauth2/auth",
            token_url="https://api.prod.whoop.com/oauth/oauth2/token",
        )

    @property
    def credentials(self) -> ProviderCredentials:
        """OAuth credentials from environment variables."""
        # Ensure `offline` is always present regardless of what's in settings
        configured_scope = settings.whoop_default_scope or WHOOP_REQUIRED_SCOPE
        scope_parts = set(configured_scope.split())
        scope_parts.add("offline")  # Guarantee offline scope for refresh token issuance
        full_scope = " ".join(sorted(scope_parts))

        return ProviderCredentials(
            client_id=settings.whoop_client_id or "",
            client_secret=(settings.whoop_client_secret.get_secret_value() if settings.whoop_client_secret else ""),
            redirect_uri=settings.whoop_redirect_uri,
            default_scope=full_scope,
        )

    # OAuth configuration
    use_pkce: bool = False  # Whoop doesn't require PKCE
    auth_method: AuthenticationMethod = AuthenticationMethod.BODY  # Credentials in request body per WHOOP docs

    def _prepare_refresh_request(self, refresh_token: str) -> tuple[dict, dict]:
        """Override to include scope in WHOOP refresh requests.

        CRITICAL: WHOOP only returns a new refresh token when `offline` is in the
        scope parameter. Without this override, refresh tokens become one-time-use
        and the athlete would need to re-authorize after the first token rotation.
        """
        token_data = {
            "grant_type": "refresh_token",
            "refresh_token": refresh_token,
            "client_id": self.credentials.client_id,
            "client_secret": self.credentials.client_secret,
            # Include scope to ensure WHOOP re-issues offline access + full scope
            "scope": self.credentials.default_scope,
        }
        headers = {"Content-Type": "application/x-www-form-urlencoded"}
        return token_data, headers

    def refresh_access_token(self, db: DbSession, user_id: UUID, refresh_token: str) -> OAuthTokenResponse:
        """Refresh WHOOP access token with post-write verification.

        Extends base implementation to verify the new refresh token was actually
        persisted to the database. Silent DB failures would cause 401s on the
        next sync cycle.
        """
        token_response = super().refresh_access_token(db, user_id, refresh_token)

        # Token verification: read back the stored token and compare first 20 chars
        # This catches silent DB failures where update_tokens returns success but
        # the value wasn't actually written (e.g. transaction not committed).
        try:
            connection = self.connection_repo.get_by_user_and_provider(db, user_id, self.provider_name)
            new_refresh = token_response.refresh_token
            if connection and new_refresh and connection.refresh_token:
                stored_prefix = connection.refresh_token[:20]
                expected_prefix = new_refresh[:20]
                if stored_prefix != expected_prefix:
                    log_structured(
                        logger,
                        "error",
                        "Token verification FAILED: stored refresh token does not match issued token",
                        provider="whoop",
                        task="refresh_access_token",
                        user_id=str(user_id),
                        stored_prefix=stored_prefix,
                        expected_prefix=expected_prefix,
                    )
                else:
                    log_structured(
                        logger,
                        "debug",
                        "Token verification passed",
                        provider="whoop",
                        task="refresh_access_token",
                        user_id=str(user_id),
                    )
        except Exception as e:
            log_structured(
                logger,
                "warning",
                f"Token verification check failed (non-fatal): {e}",
                provider="whoop",
                task="refresh_access_token",
                user_id=str(user_id),
            )

        return token_response

    def _get_provider_user_info(self, token_response: OAuthTokenResponse, user_id: str) -> dict[str, str | None]:
        """Fetches Whoop user ID via API."""
        try:
            # Whoop API endpoint to get user info
            user_info_response = httpx.get(
                f"{self.api_base_url}/v2/user/profile/basic",
                headers={"Authorization": f"Bearer {token_response.access_token}"},
                timeout=30.0,
            )
            user_info_response.raise_for_status()
            user_data = user_info_response.json()
            # Whoop API returns: user_id, email, first_name, last_name
            provider_user_id = user_data.get("user_id")
            provider_user_id = str(provider_user_id) if provider_user_id is not None else None

            log_structured(
                logger,
                "info",
                "Fetched Whoop user profile",
                provider="whoop",
                task="get_provider_user_info",
                user_id=user_id,
            )
            return {"user_id": provider_user_id, "username": None}
        except Exception as e:
            log_structured(
                logger,
                "error",
                f"Failed to fetch Whoop user profile: {e}",
                provider="whoop",
                task="get_provider_user_info",
                user_id=user_id,
            )
            return {"user_id": None, "username": None}
