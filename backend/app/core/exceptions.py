from fastapi import Request
from fastapi.responses import JSONResponse
from fastapi.exceptions import RequestValidationError
from starlette import status


async def validation_exception_handler(request: Request, exc: RequestValidationError):
    # Sanitize error details to remove non-serializable objects
    sanitized_errors = []

    for err in exc.errors():
        sanitized_errors.append(
            {
                "loc": err.get("loc"),
                "msg": str(err.get("msg")),
                "type": err.get("type"),
            }
        )

    return JSONResponse(
        status_code=status.HTTP_400_BAD_REQUEST,
        content={
            "error": "validation_error",
            "message": "Invalid request payload",
            "details": sanitized_errors,
        },
    )
