from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from fastapi import FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

from .providers.llm_provider import (
    MockTargetLLMProvider,
    TargetLLMProvider,
    TargetLLMProviderError,
    get_target_llm_provider,
)
from .schemas import (
    ErrorResponse,
    ProtectedGenerateRequest,
    ProtectedGenerateResponse,
    ScanRequest,
    ScanResponse,
    TargetLLMResponse,
)
from .services.scan_service import ScanService, ScanServiceError


def error_response(status_code: int, code: str, message: str) -> JSONResponse:
    body = ErrorResponse(error={"code": code, "message": message})
    return JSONResponse(status_code=status_code, content=body.model_dump(mode="json"))


def create_app(
    scan_service: ScanService | None = None,
    target_provider: TargetLLMProvider | None = None,
) -> FastAPI:
    # No assessor means the real Member 1/2 pipeline; injected mock assessors
    # remain explicitly available to tests through ScanService.
    service = scan_service if scan_service is not None else ScanService()
    provider = (
        target_provider
        if target_provider is not None
        else get_target_llm_provider()
    )

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        app.state.scan_service = service
        app.state.target_provider = provider
        yield

    app = FastAPI(title="PromptGuard", lifespan=lifespan)

    @app.exception_handler(RequestValidationError)
    async def validation_exception_handler(
        request: Request,
        exc: RequestValidationError,
    ) -> JSONResponse:
        message = "The request is invalid."
        if exc.errors():
            raw_message = exc.errors()[0].get("msg")
            if isinstance(raw_message, str):
                message = raw_message
        return error_response(422, "INVALID_INPUT", message)

    @app.exception_handler(HTTPException)
    async def http_exception_handler(
        request: Request,
        exc: HTTPException,
    ) -> JSONResponse:
        if isinstance(exc.detail, dict) and "code" in exc.detail and "message" in exc.detail:
            return error_response(
                exc.status_code,
                exc.detail["code"],
                exc.detail["message"],
            )
        code_by_status = {
            422: "INVALID_INPUT",
            502: "PROVIDER_OR_SERVICE_UNAVAILABLE",
            500: "INTERNAL_ERROR",
        }
        return error_response(
            exc.status_code,
            code_by_status.get(exc.status_code, "HTTP_ERROR"),
            exc.detail if isinstance(exc.detail, str) else "The request could not be completed.",
        )

    def get_scan_service(request: Request) -> ScanService:
        return request.app.state.scan_service

    def get_target_provider(request: Request) -> TargetLLMProvider:
        return request.app.state.target_provider

    @app.get("/health")
    async def health() -> dict[str, str]:
        return {"status": "ok", "service": "PromptGuard"}

    @app.post("/v1/scan", response_model=ScanResponse)
    async def scan(request: Request, body: ScanRequest) -> ScanResponse:
        try:
            return await get_scan_service(request).scan(body.text)
        except ScanServiceError:
            raise HTTPException(
                status_code=502,
                detail={
                    "code": "SCAN_FAILED",
                    "message": "Security assessment could not be completed.",
                },
            )  # type: ignore[return-value]
        except Exception:
            raise HTTPException(
                status_code=500,
                detail={
                    "code": "INTERNAL_ERROR",
                    "message": "An unexpected security assessment error occurred.",
                },
            )  # type: ignore[return-value]

    @app.post(
        "/v1/protected-generate",
        response_model=ProtectedGenerateResponse,
    )
    async def protected_generate(
        request: Request,
        body: ProtectedGenerateRequest,
    ) -> ProtectedGenerateResponse | JSONResponse:
        try:
            assessment = await get_scan_service(request).scan(body.text)
        except ScanServiceError:
            raise HTTPException(
                status_code=502,
                detail={
                    "code": "SCAN_FAILED",
                    "message": "Security assessment could not be completed.",
                },
            )
        except Exception:
            raise HTTPException(
                status_code=500,
                detail={
                    "code": "INTERNAL_ERROR",
                    "message": "An unexpected security assessment error occurred.",
                },
            )

        if assessment.decision != "ALLOW":
            return ProtectedGenerateResponse(**assessment.model_dump(), generated_response=None)

        if get_scan_service(request).is_temporary_mock:
            raise HTTPException(
                status_code=503,
                detail={
                    "code": "MOCK_SECURITY_ASSESSMENT",
                    "message": (
                        "Protected generation is unavailable because the security "
                        "assessment is a temporary mock."
                    ),
                },
            )

        try:
            provider = get_target_provider(request)
            generated = await provider.generate(body.text, body.task)
        except TargetLLMProviderError:
            raise HTTPException(
                status_code=502,
                detail={
                    "code": "TARGET_PROVIDER_FAILED",
                    "message": "The target LLM provider could not complete the request.",
                },
            )
        except Exception:
            raise HTTPException(
                status_code=502,
                detail={
                    "code": "TARGET_PROVIDER_FAILED",
                    "message": "The target LLM provider could not complete the request.",
                },
            )

        if provider.is_mock:
            generated = TargetLLMResponse(
                provider=generated.provider,
                is_mock=True,
                is_synthetic=True,
                text=f"Synthetic mock output: {generated.text}",
            )

        return ProtectedGenerateResponse(
            **assessment.model_dump(),
            generated_response=generated,
        )

    return app


app = create_app()