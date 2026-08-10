"""Authentication and API-key endpoints."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, Request, status

from app.api.deps import CurrentPrincipalDep, client_ip, get_auth_service
from app.schemas.auth import (
    ApiKeyCreate,
    ApiKeyCreatedOut,
    ApiKeyOut,
    LoginRequest,
    RefreshRequest,
    RegisterRequest,
    TokenOut,
    UserOut,
)
from app.services.auth_service import AuthService

router = APIRouter()

AuthDep = Annotated[AuthService, Depends(get_auth_service)]


@router.post("/register", response_model=UserOut, status_code=status.HTTP_201_CREATED)
async def register(payload: RegisterRequest, service: AuthDep) -> UserOut:
    user = await service.register(email=payload.email, password=payload.password)
    return UserOut.model_validate(user)


@router.post("/login", response_model=TokenOut)
async def login(payload: LoginRequest, request: Request, service: AuthDep) -> TokenOut:
    pair = await service.authenticate(
        email=payload.email, password=payload.password, ip=client_ip(request)
    )
    return TokenOut(
        access_token=pair.access_token, refresh_token=pair.refresh_token, expires_in=pair.expires_in
    )


@router.post("/refresh", response_model=TokenOut)
async def refresh(payload: RefreshRequest, service: AuthDep) -> TokenOut:
    pair = await service.refresh(payload.refresh_token)
    return TokenOut(
        access_token=pair.access_token, refresh_token=pair.refresh_token, expires_in=pair.expires_in
    )


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
async def logout(payload: RefreshRequest, request: Request, service: AuthDep) -> None:
    header = request.headers.get("authorization", "")
    access = header[7:] if header.lower().startswith("bearer ") else None
    await service.logout(payload.refresh_token, access_token=access)


@router.get("/me", response_model=UserOut)
async def me(principal: CurrentPrincipalDep, service: AuthDep) -> UserOut:
    user = await service.get_user(principal.id)
    return UserOut.model_validate(user)


@router.post("/api-keys", response_model=ApiKeyCreatedOut, status_code=status.HTTP_201_CREATED)
async def create_api_key(
    payload: ApiKeyCreate, principal: CurrentPrincipalDep, service: AuthDep
) -> ApiKeyCreatedOut:
    record, generated = await service.create_api_key(user_id=principal.id, name=payload.name)
    base = ApiKeyOut.model_validate(record)
    return ApiKeyCreatedOut(**base.model_dump(), api_key=generated.raw)


@router.get("/api-keys", response_model=list[ApiKeyOut])
async def list_api_keys(principal: CurrentPrincipalDep, service: AuthDep) -> list[ApiKeyOut]:
    keys = await service.list_api_keys(principal.id)
    return [ApiKeyOut.model_validate(k) for k in keys]


@router.get("/api-keys/{key_id}", response_model=ApiKeyOut)
async def get_api_key(key_id: str, principal: CurrentPrincipalDep, service: AuthDep) -> ApiKeyOut:
    record = await service.get_api_key(user_id=principal.id, key_id=key_id)
    return ApiKeyOut.model_validate(record)


@router.delete("/api-keys/{key_id}", status_code=status.HTTP_204_NO_CONTENT)
async def revoke_api_key(key_id: str, principal: CurrentPrincipalDep, service: AuthDep) -> None:
    await service.revoke_api_key(user_id=principal.id, key_id=key_id)
