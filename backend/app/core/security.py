from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse
from starlette import status


class SecurityMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):

        # Only enforce JSON for methods that should carry body
        if request.method in {"POST", "PUT", "PATCH"}:
            content_type = request.headers.get("content-type", "")

            if "application/json" not in content_type:
                return JSONResponse(
                    status_code=status.HTTP_415_UNSUPPORTED_MEDIA_TYPE,
                    content={
                        "error": "invalid_content_type",
                        "message": "Only application/json supported"
                    },
                )

        return await call_next(request)
