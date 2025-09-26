import httpx
from typing import Optional, Dict, Any
import logging
from datetime import datetime

from src.exceptions import APIError

class CommonHTTPClient:
    def __init__(self, base_url: str, timeout: float = 30.0, logger: logging.Logger = None):
        self.base_url = base_url.rstrip('/')
        self.timeout = timeout
        self._logger = logger or logging.getLogger(__name__)

    async def __aenter__(self):
        self._client = httpx.AsyncClient(
            base_url=self.base_url,
            timeout=self.timeout,
            headers={"Content-Type": "application/json"}
        )
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self._client:
            await self._client.aclose()

    def set_auth_token(self, token: str):
        if self._client:
            self._client.headers["Authorization"] = f"Bearer {token}"

    async def get(self, endpoint: str, params: Optional[Dict] = None) -> Dict[str, Any]:
        return await self._request("GET", endpoint, params=params)

    async def post(self, endpoint: str, data: Dict[str, Any]) -> Dict[str, Any]:
        return await self._request("POST", endpoint, json=data)

    async def put(self, endpoint: str, data: Dict[str, Any]) -> Dict[str, Any]:
        return await self._request("PUT", endpoint, json=data)

    async def _request(self, method: str, endpoint: str, **kwargs) -> Dict[str, Any]:
        if not self._client:
            raise RuntimeError("HTTP клиент не инициализирован")

        url = f"{self.base_url}/{endpoint.lstrip('/')}"

        try:
            self._logger.debug(f"HTTP {method} {url}")
            response = await self._client.request(method, url, **kwargs)
            response.raise_for_status()
            return response.json() if response.content else {}

        except httpx.HTTPStatusError as e:
            error_message = f"HTTP error {e.response.status_code}: {e.response.text}"
            self._logger.error(error_message)

            raise APIError(
                message=f"API error: {e.response.status_code}",
                status_code=e.response.status_code,
                response_data=e.response.json() if e.response.content else None
            ) from e

        except httpx.RequestError as e:
            error_message = f"Network error: {str(e)}"
            self._logger.error(error_message)
            raise NetworkError(f"Network error: {str(e)}") from e

        except Exception as e:
            error_message = f"Unexpected error: {str(e)}"
            self._logger.error(error_message)
            raise InfrastructureError(f"Unexpected error: {str(e)}") from e