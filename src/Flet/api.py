import httpx

BASE_URL = "http://localhost:8000"

async def api_request(endpoint: str, method: str = "GET", data: dict | None = None) -> dict | None:
    """Асинхронный HTTP-запрос к API"""
    try:
        async with httpx.AsyncClient() as client:
            if method == "GET":
                response = await client.get(f"{BASE_URL}{endpoint}")
            elif method == "POST":
                response = await client.post(
                    f"{BASE_URL}{endpoint}",
                    json=data,
                    headers={"Content-Type": "application/json"},
                )
            response.raise_for_status()
            return response.json()
    except httpx.HTTPStatusError as e:
        print(f"HTTP error: {e}")
        return None
    except httpx.RequestError as e:
        print(f"Request error: {e}")
        return None
    except Exception as e:
        print(f"API error: {e}")
        return None